const mongoose = require("mongoose");
const bcrypt = require("bcryptjs"); // משיכת ספרייה
const jwt = require("jsonwebtoken");

const UserSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, "בבקשה רשום שם"],
    minlength: 3,
    maxlength: 20,
  },

  email: {
    type: String,
    required: [true, "בבקשה רשום מייל תיקני"],
    // קוד לבדיקת התאמה של מייל
    match: [
      /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/,
      " Please provide valid email",
    ],
    unique: true,
  },
  password: {
    type: String,
    required: [true, "בבקשה רשום סיסמא"],
    minlength: 6,
  },
});

// פונקציונליות בשביל להצפין את הסיסמא
UserSchema.pre("save", async function() {
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
});

// פנקציה בשביל סנכרון השם
UserSchema.methods.createJWT = function() {
  return jwt.sign(
    { userId: this._id, name: this.name },
    process.env.JWT_SECRET,
    {
      expiresIn: process.env.JWT_LIFETIME,
    }
  );
};

// השוואה בין הסיסמא המוצפנת לסיסמא השמורה במסד הנתונים
UserSchema.methods.comparePassword = async function(canditatePassword) {
  const isMatch = await bcrypt.compare(canditatePassword, this.password); // bcrypt.compare קישור לחבילה ולפנוקציית בדיקה
  return isMatch; // מחזירים התאמה אם מצליח
};

module.exports = mongoose.model("User", UserSchema);
