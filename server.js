
require("dotenv").config();

const express = require("express");
const http = require("http");
const path = require("path");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  maxHttpBufferSize: 7e6
});

app.use(express.json({ limit: "7mb" }));
app.use(express.static(path.join(__dirname, "public")));

const User = mongoose.model("User", new mongoose.Schema({
  username: {
    type: String,
    unique: true,
    required: true,
    minlength: 3,
    maxlength: 24
  },
  passwordHash: { type: String, required: true },
  publicId: { type: String, unique: true, required: true },
  createdAt: { type: Date, default: Date.now }
}));

const Group = mongoose.model("Group", new mongoose.Schema({
  groupId: { type: String, unique: true, required: true },
  name: { type: String, required: true, maxlength: 60 },
  members: { type: [String], required: true },
  createdBy: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
}));

const Message = mongoose.model("Message", new mongoose.Schema({
  roomId: { type: String, required: true, index: true },
  from: { type: String, required: true },
  fromName: { type: String, required: true },
  text: { type: String, default: "", maxlength: 4000 },
  media: {
    kind: { type: String, enum: ["image", "audio"] },
    data: { type: String, maxlength: 6500000 },
    mime: String,
    name: String
  },
  createdAt: { type: Date, default: Date.now }
}));

Message.schema.index({ roomId: 1, createdAt: 1 });

const SECRET = process.env.JWT_SECRET;
const online = new Map();

function makeId(prefix) {
  return prefix + "-" + crypto.randomBytes(3).toString("hex").toUpperCase();
}

function directRoom(a, b) {
  return "dm:" + [a, b].sort().join(":");
}

function safeUser(u) {
  return { username: u.username, publicId: u.publicId };
}

function makeToken(u) {
  return jwt.sign({
    uid: String(u._id),
    username: u.username,
    publicId: u.publicId
  }, SECRET, { expiresIn: "7d" });
}

function authenticate(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ")
      ? header.slice(7)
      : "";

    req.user = jwt.verify(token, SECRET);
    next();
  } catch {
    res.status(401).json({ error: "سجّل الدخول من جديد." });
  }
}

async function canAccessRoom(roomId, userId) {
  if (roomId.startsWith("dm:")) {
    const ids = roomId.slice(3).split(":");
    return ids.length === 2 && ids.includes(userId);
  }

  return !!(await Group.exists({
    groupId: roomId,
    members: userId
  }));
}

function emitPresence() {
  io.emit("presence-list", [...online.keys()]);
}

app.get("/api/health", (_req, res) => {
  res.json({ ok: true });
});

// إنشاء حساب
app.post("/api/register", async (req, res) => {
  try {
    const username = String(req.body.username || "")
      .trim().toLowerCase();
    const password = String(req.body.password || "");

    if (!/^[a-z0-9_]{3,24}$/.test(username)) {
      return res.status(400).json({
        error: "اسم المستخدم يجب أن يكون 3-24 حرفاً أو رقماً."
      });
    }

    if (password.length < 8 || password.length > 128) {
      return res.status(400).json({
        error: "كلمة السر يجب أن تكون بين 8 و128 حرفاً."
      });
    }

    const user = await User.create({
      username,
      passwordHash: await bcrypt.hash(password, 12),
      publicId: makeId("MX")
    });

    res.json({
      token: makeToken(user),
      user: safeUser(user)
    });
  } catch (err) {
    if (err.code === 11000) {
      return res.status(409).json({
        error: "اسم المستخدم مستعمل."
      });
    }

    console.error(err);
    res.status(500).json({ error: "تعذر إنشاء الحساب." });
  }
});

// تسجيل الدخول
app.post("/api/login", async (req, res) => {
  try {
    const username = String(req.body.username || "")
      .trim().toLowerCase();
    const password = String(req.body.password || "");

    const user = await User.findOne({ username });

    if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
      return res.status(401).json({
        error: "اسم المستخدم أو كلمة السر غير صحيحة."
      });
    }

    res.json({
      token: makeToken(user),
      user: safeUser(user)
    });
  } catch {
    res.status(500).json({ error: "تعذر تسجيل الدخول." });
  }
});

app.get("/api/me", authenticate, async (req, res) => {
  res.json({
    user: {
      username: req.user.username,
      publicId: req.user.publicId
    }
  });
});

// قائمة الحسابات
app.get("/api/users", authenticate, async (req, res) => {
  const users = await User.find({
    publicId: { $ne: req.user.publicId }
  }).select("username publicId").limit(100);

  res.json({ users: users.map(safeUser) });
});

app.get("/api/users/:id", authenticate, async (req, res) => {
  const user = await User.findOne({
    publicId: String(req.params.id).toUpperCase()
  }).select("username publicId");

  if (!user) {
    return res.status(404).json({
      error: "هذا المستخدم غير موجود."
    });
  }

  res.json({ user: safeUser(user) });
});

// إنشاء مجموعة
app.post("/api/groups", authenticate, async (req, res) => {
  try {
    const name = String(req.body.name || "").trim();
    const ids = Array.isArray(req.body.members)
      ? req.body.members.map(x => String(x).trim().toUpperCase())
      : [];

    if (name.length < 2 || name.length > 60) {
      return res.status(400).json({
        error: "اسم المجموعة يجب أن يكون بين 2 و60 حرفاً."
      });
    }

    const members = [...new Set([
      req.user.publicId,
      ...ids
    ])];

    if (members.length < 2 || members.length > 50) {
      return res.status(400).json({
        error: "أضف عضواً واحداً على الأقل، وبحد أقصى 50 عضواً."
      });
    }

    const count = await User.countDocuments({
      publicId: { $in: members }
    });

    if (count !== members.length) {
      return res.status(400).json({
        error: "يوجد ID غير صحيح."
      });
    }

    const group = await Group.create({
      groupId: makeId("GR"),
      name,
      members,
      createdBy: req.user.publicId
    });

    res.json({
      group: {
        groupId: group.groupId,
        name: group.name,
        members: group.members
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: "تعذر إنشاء المجموعة."
    });
  }
});

app.get("/api/groups", authenticate, async (req, res) => {
  const groups = await Group.find({
    members: req.user.publicId
  }).sort({ createdAt: -1 }).lean();

  res.json({
    groups: groups.map(g => ({
      groupId: g.groupId,
      name: g.name,
      members: g.members
    }))
  });
});

// سجل الرسائل: لا يستطيع المستخدم قراءة غرفة ليس عضواً فيها
app.get("/api/messages/:roomId", authenticate, async (req, res) => {
  const roomId = String(req.params.roomId);

  if (!(await canAccessRoom(roomId, req.user.publicId))) {
    return res.status(403).json({
      error: "ليس لديك صلاحية لهذه المحادثة."
    });
  }

  const messages = await Message.find({ roomId })
    .sort({ createdAt: 1 })
    .limit(100)
    .lean();

  res.json({ messages });
});

// المصادقة على Socket.IO
io.use((socket, next) => {
  try {
    socket.user = jwt.verify(
      socket.handshake.auth?.token,
      SECRET
    );
    next();
  } catch {
    next(new Error("غير مصرح"));
  }
});

io.on("connection", socket => {
  const me = socket.user.publicId;

  if (!online.has(me)) online.set(me, new Set());
  online.get(me).add(socket.id);
  emitPresence();

  socket.on("join-room", async ({ roomId } = {}) => {
    roomId = String(roomId || "");

    if (await canAccessRoom(roomId, me)) {
      for (const room of socket.rooms) {
        if (room !== socket.id) socket.leave(room);
      }
      socket.join(roomId);
    }
  });

  // رسائل خاصة
  socket.on("private-message", async payload => {
    try {
      const to = String(payload.to || "").toUpperCase();
      const text = String(payload.text || "").trim();

      if (!text || text.length > 4000 || to === me) return;

      const recipient = await User.findOne({
        publicId: to
      }).select("publicId");

      if (!recipient) {
        return socket.emit("chat-error", "المستخدم غير موجود.");
      }

      const roomId = directRoom(me, to);
      const msg = await Message.create({
        roomId,
        from: me,
        fromName: socket.user.username,
        text
      });

      const item = msg.toObject();

      for (const sid of online.get(me) || []) {
        io.to(sid).emit("private-message", item);
      }

      for (const sid of online.get(to) || []) {
        io.to(sid).emit("private-message", item);
      }
    } catch (err) {
      console.error(err);
      socket.emit("chat-error", "تعذر إرسال الرسالة.");
    }
  });

  // رسائل المجموعات
  socket.on("group-message", async payload => {
    try {
      const roomId = String(payload.roomId || "");
      const text = String(payload.text || "").trim();

      if (!text || text.length > 4000) return;
      if (!(await canAccessRoom(roomId, me))) return;

      const msg = await Message.create({
        roomId,
        from: me,
        fromName: socket.user.username,
        text
      });

      io.to(roomId).emit("private-message", msg.toObject());
    } catch {
      socket.emit("chat-error", "تعذر إرسال رسالة المجموعة.");
    }
  });

  // الصور والتسجيلات الصوتية محفوظة في MongoDB
  socket.on("media-message", async payload => {
    try {
      const roomId = String(payload.roomId || "");
      const kind = payload.kind;
      const data = String(payload.data || "");
      const mime = String(payload.mime || "");

      const allowed = {
        image: /^data:image\/(png|jpeg|gif|webp);base64,/,
        audio: /^data:audio\/(webm|ogg|mpeg|mp4|wav);base64,/
      };

      if (!allowed[kind]?.test(data) || data.length > 6500000) {
        return socket.emit("chat-error", "نوع الملف غير مدعوم أو حجمه كبير.");
      }

      if (!(await canAccessRoom(roomId, me))) return;

      const msg = await Message.create({
        roomId,
        from: me,
        fromName: socket.user.username,
        media: {
          kind,
          data,
          mime,
          name: String(payload.name || "media").slice(0, 180)
        }
      });

      const item = msg.toObject();

      if (roomId.startsWith("dm:")) {
        const ids = roomId.slice(3).split(":");
        for (const id of ids) {
          for (const sid of online.get(id) || []) {
            io.to(sid).emit("private-message", item);
          }
        }
      } else {
        io.to(roomId).emit("private-message", item);
      }
    } catch (err) {
      console.error(err);
      socket.emit("chat-error", "تعذر حفظ الوسائط.");
    }
  });

  // إشارات المكالمات الفردية والجماعية
  socket.on("call-signal", async ({ to, roomId, data } = {}) => {
    roomId = String(roomId || "");
    to = String(to || "").toUpperCase();

    if (!(await canAccessRoom(roomId, me))) return;

    if (roomId.startsWith("dm:")) {
      const ids = roomId.slice(3).split(":");
      const recipientId = ids.find(id => id !== me);
      if (!recipientId || (to && to !== recipientId)) return;

      for (const sid of online.get(recipientId) || []) {
        io.to(sid).emit("call-signal", {
          from: me,
          fromName: socket.user.username,
          roomId,
          data
        });
      }
    } else {
      // توصيل الإشارة إلى أعضاء المجموعة فقط.
      const group = await Group.findOne({
        groupId: roomId,
        members: me
      });

      if (!group) return;

      for (const member of group.members) {
        if (member === me) continue;

        for (const sid of online.get(member) || []) {
          io.to(sid).emit("call-signal", {
            from: me,
            fromName: socket.user.username,
            roomId,
            data
          });
        }
      }
    }
  });

  socket.on("disconnect", () => {
    const sockets = online.get(me);

    if (sockets) {
      sockets.delete(socket.id);
      if (!sockets.size) online.delete(me);
    }

    emitPresence();
  });
});

async function start() {
  if (!SECRET || SECRET.length < 32) {
    throw new Error("JWT_SECRET must contain at least 32 characters.");
  }

  if (!process.env.MONGODB_URI) {
    throw new Error("MONGODB_URI is missing.");
  }

  await mongoose.connect(process.env.MONGODB_URI);

  const port = process.env.PORT || 3000;
  server.listen(port, () => {
    console.log("CYBER CHAT MATRIX running on port " + port);
  });
}

start().catch(err => {
  console.error(err);
  process.exit(1);
});
