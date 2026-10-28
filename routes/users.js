const express = require("express");
const bcrypt = require("bcryptjs");

const User = require("../models/User");
const Role = require("../models/Role");

const { authenticate, requirePermission } = require("../middleware/auth");
const { missingPermissions, isLastSuperAdmin } = require("../utils/rbac");
const {
  fail,
  detail,
  notAllowedFields,
  isObjectId,
  parsePaging,
  parseSort,
  escapeRegex,
  pageMeta,
  userView,
  roleSummary,
} = require("../utils/http");

const router = express.Router();

router.use(authenticate); // mọi endpoint dưới đây đều cần đăng nhập

// Middleware nạp user theo :userId (bỏ qua user đã xóa mềm)
async function loadUser(req, res, next) {
  const { userId } = req.params;
  const user = isObjectId(userId)
    ? await User.findOne({ _id: userId, status: { $ne: "deleted" } }).populate(
        "roles",
      )
    : null;
  if (!user)
    return fail(res, 404, "USER_NOT_FOUND", "Không tìm thấy người dùng.");
  req.target = user;
  next();
}

// TODO: loadRole tương tự, trả 404 ROLE_NOT_FOUND
async function loadRole(req, res, next) {
  const { roleId } = req.params;
  const role = isObjectId(roleId) ? await Role.findOne({ _id: roleId }) : null;
  if (!role) return fail(res, 404, "ROLE_NOT_FOUND", "Không tìm thấy role.");
  req.target = role;
  next();
}

router.get("/", requirePermission("users:read"), async (req, res) => {
  const q = req.query;
  const details = [];
  const { page, limit } = parsePaging(q, details);
  const sort = parseSort(
    q.sort || "-createdAt",
    ["fullName", "email", "createdAt", "lastLoginAt"],
    details,
  );
  if (q.status && !["active", "locked"].includes(q.status))
    details.push(
      detail("status", "INVALID_VALUE", "status phải là active hoặc locked."),
    );
  // TODO: kiểm tra roleId (ObjectId hợp lệ) và q (tối thiểu 2 ký tự)
  if (details.length)
    return fail(
      res,
      400,
      "INVALID_QUERY_PARAMETER",
      "Tham số truy vấn không hợp lệ.",
      details,
    );
  const filter = { status: q.status || { $ne: "deleted" } };
  if (q.roleId) filter.roles = q.roleId; // mảng chứa phần tử roleId
  if (q.q) {
    const re = { $regex: escapeRegex(String(q.q).trim()), $options: "i" };
    filter.$or = [{ fullName: re }, { email: re }];
  }
  const [items, totalItems] = await Promise.all([
    User.find(filter)
      .sort({ ...sort, _id: 1 })
      .skip((page - 1) * limit)
      .limit(limit)
      .populate("roles"),
    User.countDocuments(filter),
  ]);
  res.json({
    data: items.map(userView),
    meta: pageMeta(page, limit, totalItems),
  });
});

const PASSWORD_RE = /^(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$/;
router.post("/", requirePermission("users:create"), async (req, res) => {
  const body = req.body || {};
  // 1. Allow-list: chỉ nhận các trường này
  const details = notAllowedFields(body, [
    "email",
    "fullName",
    "phone",
    "password",
    "roleIds",
  ]);
  if (!body.password)
    details.push(
      detail("password", "REQUIRED", "Mật khẩu không được để trống."),
    );
  else if (!PASSWORD_RE.test(body.password))
    details.push(
      detail(
        "password",
        "WEAK_PASSWORD",
        "Mật khẩu tối thiểu 8 ký tự, có chữ hoa, chữ số và ký tự đặc biệt.",
      ),
    );
  // TODO: roleIds (nếu có) phải là mảng ObjectId hợp lệ
  if (details.length)
    return fail(
      res,
      400,
      "VALIDATION_ERROR",
      "Dữ liệu đầu vào không hợp lệ.",
      details,
    );
  // 2. Vai trò: có roleIds -> cần roles:assign, mọi role phải tồn tại, không vượt quyền người gọi
  let roles = [];
  const roleIds = [...new Set(body.roleIds || [])];
  if (roleIds.length) {
    if (!req.permissions.has("roles:assign"))
      return fail(
        res,
        403,
        "FORBIDDEN",
        "Gán role khi tạo người dùng cần quyền roles:assign.",
      );
    roles = await Role.find({ _id: { $in: roleIds } });
    if (roles.length !== roleIds.length)
      return fail(
        res,
        400,
        "ROLE_NOT_FOUND",
        "Có role không tồn tại trong roleIds.",
      );
    // TODO: dùng missingPermissions(...) -> 403 PRIVILEGE_ESCALATION
  } else {
    roles = await Role.find({ code: "member" }); // mặc định
  }
  // 3. Email trùng -> 409 (kiểm tra trước để trả lỗi rõ ràng; unique index là lưới an toàn)
  if (
    body.email &&
    (await User.exists({ email: String(body.email).trim().toLowerCase() }))
  )
    return fail(res, 409, "EMAIL_ALREADY_EXISTS", "Email đã được sử dụng.");
  // 4. Tạo – lỗi validation của schema được error handler chuyển thành 400
  const user = await User.create({
    email: body.email,
    fullName: body.fullName,
    phone: body.phone ?? null,
    passwordHash: await bcrypt.hash(body.password, 10),
    roles: roles.map((r) => r._id),
  });
  await user.populate("roles");
  res.status(201).location(`${req.baseUrl}/${user._id}`).json(userView(user));
});

router.get("/:userId", requirePermission("users:read"), loadUser, (req, res) =>
  res.json(userView(req.target)),
);

router.patch(
  "/:userId",
  requirePermission("users:update"),
  loadUser,
  async (req, res) => {
    /* 2.5 */
  },
);

router.delete(
  "/:userId",
  requirePermission("users:delete"),
  loadUser,
  async (req, res) => {
    /* 2.6 */
  },
);

router.get(
  "/:userId/roles",
  requirePermission("users:read"),
  loadUser,
  (req, res) => {
    /* TODO */
  },
);

router.put(
  "/:userId/roles/:roleId",
  requirePermission("roles:assign"),
  loadUser,
  loadRole,
  async (req, res) => {
    /* 2.7 */
  },
);

router.delete(
  "/:userId/roles/:roleId",
  requirePermission("roles:assign"),
  loadUser,
  loadRole,
  async (req, res) => {
    /* 2.7 */
  },
);

module.exports = router;
