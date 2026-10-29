const express = require("express");
const Permission = require("../models/Permission");
const { authenticate, requirePermission } = require("../middleware/auth");

const router = express.Router();

router.use(authenticate)

router.get("/", requirePermission("permissions:read"), async (req, res) => {
  // ?resource=users -> chỉ lấy quyền của resource đó
  const filter = {};
  if (req.query.resource) filter.resource = String(req.query.resource);

  const permissions = await Permission.find(filter).sort({ resource: 1, code: 1 });
  const data = permissions.map((p) => ({
    code: p.code,
    resource: p.resource,
    action: p.action,
    description: p.description,
  }));
  res.json({ data, meta: { totalItems: data.length } });
});

module.exports = router;
