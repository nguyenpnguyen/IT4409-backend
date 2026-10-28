const mongoose = require("mongoose");

// Gửi lỗi theo định dạng thống nhất { error: { code, message, details? } }
function fail(res, status, code, message, details) {
  const error = { code, message };
  if (details && details.length) error.details = details;
  return res.status(status).json({ error });
}
const detail = (field, issue, message) => ({ field, issue, message });

// Lỗi cho các trường không nằm trong allow-list (chống mass assignment)
function notAllowedFields(body, allowed) {
  return Object.keys(body || {})
    .filter((k) => !allowed.includes(k))
    .map((k) =>
      detail(
        k,
        "FIELD_NOT_ALLOWED",
        `Trường '${k}' không được phép gửi lên endpoint này.`,
      ),
    );
}

const isObjectId = (id) =>
  mongoose.isValidObjectId(id) &&
  String(new mongoose.Types.ObjectId(id)) === String(id);

// Đọc và kiểm tra page/limit
function parsePaging(query, details) {
  const page = query.page === undefined ? 1 : Number(query.page);
  const limit = query.limit === undefined ? 10 : Number(query.limit);
  if (!Number.isInteger(page) || page < 1)
    details.push(
      detail("page", "INVALID_VALUE", "page phải là số nguyên ≥ 1."),
    );
  if (!Number.isInteger(limit) || limit < 1 || limit > 100)
    details.push(
      detail("limit", "OUT_OF_RANGE", "limit phải trong khoảng 1–100."),
    );
  return { page, limit };
}
// sort=-createdAt,fullName -> { createdAt: -1, fullName: 1 }
function parseSort(raw, allowed, details) {
  const sort = {};
  for (const part of String(raw)
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)) {
    const field = part.replace(/^-/, "");
    if (!allowed.includes(field)) {
      details.push(
        detail(
          "sort",
          "FIELD_NOT_SORTABLE",
          `Không sắp xếp được theo '${field}'.`,
        ),
      );
      continue;
    }
    sort[field] = part.startsWith("-") ? -1 : 1;
  }
  return sort;
}

// Thoát ký tự đặc biệt trước khi đưa từ khóa vào $regex
const escapeRegex = (s) => String(s).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const pageMeta = (page, limit, totalItems) => ({
  page,
  limit,
  totalItems,
  totalPages: Math.max(1, Math.ceil(totalItems / limit)),
});

// ---- Biểu diễn tài nguyên: CHỈ chọn trường được phép trả ra ----
const roleSummary = (r) => ({ id: String(r._id), code: r.code, name: r.name });
function userView(u) {
  return {
    id: String(u._id),
    email: u.email,
    fullName: u.fullName,
    phone: u.phone,
    status: u.status,
    roles: (u.roles || []).filter((r) => r && r.code).map(roleSummary),
    lastLoginAt: u.lastLoginAt,
    createdAt: u.createdAt,
    updatedAt: u.updatedAt,
  };
}

function roleView(r, userCount) {
  return {
    id: String(r._id),
    code: r.code,
    name: r.name,
    description: r.description,
    isSystem: r.isSystem,
    permissions: [...r.permissions],
    userCount,
    createdAt: r.createdAt,
    updatedAt: r.updatedAt,
  };
}

module.exports = {
  fail,
  detail,
  notAllowedFields,
  isObjectId,
  parsePaging,
  parseSort,
  escapeRegex,
  pageMeta,
  userView,
  roleView,
  roleSummary,
};
