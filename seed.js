require("dotenv").config();

const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const Permission = require("./models/Permission");
const Role = require("./models/Role");
const User = require("./models/User");

const PERMISSIONS = [
  ["users:read", "Xem danh sách và chi tiết người dùng"],
  ["users:create", "Tạo người dùng"],
  ["users:update", "Sửa thông tin, khóa/mở khóa người dùng"],
  ["users:delete", "Xóa người dùng"],
  ["roles:read", "Xem role và quyền của role"],
  ["roles:create", "Tạo role"],
  ["roles:update", "Sửa role, thay bộ quyền của role"],
  ["roles:delete", "Xóa role"],
  ["roles:assign", "Gán / gỡ role cho người dùng"],
  ["permissions:read", "Xem danh mục quyền"],
].map(([code, description]) => ({
  code,
  resource: code.split(":")[0],
  action: code.split(":")[1],
  description,
}));

const userManagerPermissions = ["users:read", "users:create", "users:update", "roles:read", "roles:assign", "permissions:read"]
const auditorPermissions = ["users:read", "roles:read", "permissions:read"]

const ROLES = [
  {
    code: "super-admin",
    name: "Quản trị viên tối cao",
    isSystem: true,
    permissions: PERMISSIONS.map((p) => p.code),
  },
  // TODO: user-manager, auditor, member theo ma trận ở mục II.1.5
  {
    code: "user-manager",
    name: "Quản lý",
    isSystem: true,
    permissions: PERMISSIONS.filter((p) => userManagerPermissions.includes(p.code)).map((p) => p.code),
  },
  {
    code: "auditor",
    name: "Kiểm toán viên",
    isSystem: true,
    permissions: PERMISSIONS.filter((p) => auditorPermissions.includes(p.code)).map((p) => p.code),
  },
  {
    code: "member",
    name: "Người dùng",
    isSystem: true,
    permissions: [],
  },
];

// TODO: dữ liệu THẬT theo yêu cầu "Dữ liệu tối thiểu" (mục 1.11)
const USERS = [
  {
    email: "20261222M@sis.hust.edu.vn",
    fullName: "Nguyễn Phúc Nguyên",
    phone: "+84398095097",
    password: "Admin@2026",
    roles: ["super-admin"],
  },
  {
    email: "20252582M@sis.hust.edu.vn",
    fullName: "Nguyễn Đức Huy",
    phone: "+84123456789",
    password: "Manager@2026",
    roles: ["user-manager"],
  },
  {
    email: "20252092M@sis.hust.edu.vn",
    fullName: "Nguyễn Đức Huy",
    phone: "+84987654321",
    password: "Auditor@2026",
    roles: ["auditor"],
  },
  {
    email: "20252011M@sis.hust.edu.vn",
    fullName: "Lê Hữu Thành",
    phone: "+84876543210",
    password: "Member@2026",
    roles: ["member"],
  },
];

(async () => {
  await mongoose.connect(process.env.MONGODB_URI);
  await Promise.all([
    Permission.deleteMany({}),
    Role.deleteMany({}),
    User.deleteMany({}),
  ]);
  await Promise.all([Permission.init(), Role.init(), User.init()]); // tạo unique index;
  await Permission.insertMany(PERMISSIONS);
  const roles = await Role.insertMany(ROLES);
  const roleId = Object.fromEntries(roles.map((r) => [r.code, r._id]));
  for (const u of USERS) {
    await User.create({
      email: u.email,
      fullName: u.fullName,
      phone: u.phone ?? null,
      passwordHash: await bcrypt.hash(u.password, 10),
      roles: u.roles.map((code) => roleId[code]),
    });
  }
  console.log(
    `Đã tạo ${PERMISSIONS.length} quyền, ${roles.length} role, ${USERS.length} người dùng.`,
  );
  await mongoose.disconnect();
})();
