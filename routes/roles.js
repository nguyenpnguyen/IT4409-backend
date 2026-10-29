const express = require("express");

const User = require("../models/User");
const Role = require("../models/Role");
const Permission = require("../models/Permission");

const { authenticate, requirePermission } = require("../middleware/auth");
const { missingPermissions } = require("../utils/rbac");
const {
  fail,
  detail,
  notAllowedFields,
  isObjectId,
  parsePaging,
  parseSort,
  escapeRegex,
  pageMeta,
  roleView,
} = require("../utils/http");

const router = express.Router();

router.use(authenticate)

// Middleware nạp role theo :roleId
async function loadRole(req, res, next) {
  const { roleId } = req.params;
  const role = isObjectId(roleId) ? await Role.findById(roleId) : null;
  if (!role) return fail(res, 404, "ROLE_NOT_FOUND", "Không tìm thấy role.");
  req.target = role;
  next();
}

// Số người dùng (chưa bị xóa) đang mang role
const countUsers = (roleId) =>
  User.countDocuments({ roles: roleId, status: { $ne: "deleted" } });

// Kiểm tra mảng mã quyền: đúng kiểu và tồn tại trong danh mục
async function checkPermissionList(perms) {
  if (!Array.isArray(perms) || !perms.every((p) => typeof p === "string"))
    return {
      status: 400,
      code: "VALIDATION_ERROR",
      message: "Dữ liệu đầu vào không hợp lệ.",
      details: [
        detail("permissions", "INVALID_TYPE", "permissions phải là mảng mã quyền."),
      ],
    };
  const known = new Set(
    (await Permission.find({ code: { $in: perms } })).map((p) => p.code),
  );
  const unknown = perms.filter((p) => !known.has(p));
  if (unknown.length)
    return {
      status: 400,
      code: "PERMISSION_NOT_FOUND",
      message: "Có quyền không tồn tại trong danh mục.",
      details: unknown.map((p) =>
        detail("permissions", "NOT_FOUND", `Quyền '${p}' không tồn tại.`),
      ),
    };
  return null;
}

router.get("/", requirePermission("roles:read"), async (req, res) => {
  const q = req.query;
  const details = [];
  const { page, limit } = parsePaging(q, details);
  const sort = parseSort(q.sort || "name", ["name", "code", "createdAt"], details);
  if (details.length)
    return fail(
      res,
      400,
      "INVALID_QUERY_PARAMETER",
      "Tham số truy vấn không hợp lệ.",
      details,
    );

  // q tìm trong name hoặc code
  const filter = {};
  if (q.q) {
    const re = { $regex: escapeRegex(String(q.q).trim()), $options: "i" };
    filter.$or = [{ name: re }, { code: re }];
  }

  const [roles, totalItems] = await Promise.all([
    Role.find(filter)
      .sort({ ...sort, _id: 1 })
      .skip((page - 1) * limit)
      .limit(limit),
    Role.countDocuments(filter),
  ]);
  const counts = await Promise.all(roles.map((r) => countUsers(r._id)));

  res.json({
    data: roles.map((r, i) => roleView(r, counts[i])),
    meta: pageMeta(page, limit, totalItems),
  });
});

router.post("/", requirePermission("roles:create"), async (req, res) => {
  const body = req.body || {};
  const details = notAllowedFields(body, ["code", "name", "description", "permissions"]);
  if (details.length)
    return fail(res, 400, "VALIDATION_ERROR", "Dữ liệu đầu vào không hợp lệ.", details);
  // Danh sách quyền (không gửi thì role rỗng)
  const err = await checkPermissionList(body.permissions ?? []);
  if (err) return fail(res, err.status, err.code, err.message, err.details);
  const permissions = [...new Set(body.permissions ?? [])];
  //Chống leo thang (BR-02): chỉ được cấp quyền mình đang có
  const missing = missingPermissions(permissions, req.permissions);
  if (missing.length > 0)
    return fail(
      res,
      403,
      "PRIVILEGE_ESCALATION",
      `Không thể cấp quyền bạn không có: ${missing.join(", ")}.`,
    );
  // Trùng code -> 409 (BR-01)
  if (body.code && (await Role.exists({ code: String(body.code).trim() })))
    return fail(res, 409, "ROLE_CODE_EXISTS", "Mã role đã tồn tại.");

  // Tạo – lỗi validation của schema được error handler chuyển thành 400
  const role = await Role.create({
    code: body.code,
    name: body.name,
    description: body.description ?? null,
    permissions,
  });
  res.status(201).location(`${req.baseUrl}/${role._id}`).json(roleView(role, 0));
});

router.get("/:roleId", requirePermission("roles:read"), loadRole, async (req, res) => {
  const role = req.target;
  res.json(roleView(role, await countUsers(role._id)));
});

router.patch("/:roleId", requirePermission("roles:update"), loadRole, async (req, res) => {
  const body = req.body || {};
  const role = req.target;
  // Chỉ nhận name, description
  const details = notAllowedFields(body, ["name", "description"]);
  if (details.length)
    return fail(res, 400, "VALIDATION_ERROR", "Dữ liệu đầu vào không hợp lệ.", details);

  for (const k of ["name", "description"]) if (k in body) role[k] = body[k];
  await role.save();
  res.json(roleView(role, await countUsers(role._id)));
});

router.delete("/:roleId", requirePermission("roles:delete"), loadRole, async (req, res) => {
  const role = req.target;
  // BR-05: role hệ thống không được xóa
  if (role.isSystem)
    return fail(res, 409, "SYSTEM_ROLE_PROTECTED", "Không thể xóa role hệ thống.");
  // BR-06: role đang được gán cho người dùng thì không xóa
  if ((await countUsers(role._id)) > 0)
    return fail(res, 409, "ROLE_IN_USE", "Role đang được gán cho người dùng.");

  await role.deleteOne();
  res.status(204).end();
});

router.get(
  "/:roleId/permissions",
  requirePermission("roles:read"),
  loadRole,
  async (req, res) => {
    const permissions = await Permission.find({
      code: { $in: req.target.permissions },
    }).sort({ resource: 1, code: 1 });
    const data = permissions.map((p) => ({
      code: p.code,
      resource: p.resource,
      action: p.action,
      description: p.description,
    }));
    res.json({ data, meta: { totalItems: data.length } });
  },
);

router.put(
  "/:roleId/permissions",
  requirePermission("roles:update"),
  loadRole,
  async (req, res) => {
    const body = req.body || {};
    const role = req.target;
    // kiểm tra danh sách quyền
    const details = notAllowedFields(body, ["permissions"]);
    if (details.length)
      return fail(res, 400, "VALIDATION_ERROR", "Dữ liệu đầu vào không hợp lệ.", details);
    const err = await checkPermissionList(body.permissions);
    if (err) return fail(res, err.status, err.code, err.message, err.details);
    // BR-05: role hệ thống không được đổi bộ quyền
    if (role.isSystem)
      return fail(
        res,
        409,
        "SYSTEM_ROLE_PROTECTED",
        "Không thể đổi bộ quyền của role hệ thống.",
      );
    // BR-02: chống leo thang
    const newPermissions = [...new Set(body.permissions)];
    const added = newPermissions.filter((p) => !role.permissions.includes(p));
    const removed = role.permissions.filter((p) => !newPermissions.includes(p));
    const missing = missingPermissions([...added, ...removed], req.permissions);
    if (missing.length > 0)
      return fail(
        res,
        403,
        "PRIVILEGE_ESCALATION",
        `Không thể thêm/bớt quyền bạn không có: ${missing.join(", ")}.`,
      );

    role.permissions = newPermissions;
    await role.save();
    res.json(roleView(role, await countUsers(role._id)));
  },
);

module.exports = router;
