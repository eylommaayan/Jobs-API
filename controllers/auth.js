const User = require("../models/User");
const { StatusCodes } = require("http-status-codes"); // שימוש בספרייה
const { BadRequestError, UnauthenticatedError } = require("../errors"); // קישור לקובץ שרשום בו פונקציית השגיאה

// מה שהמשתמש רושם יכנס לגוף ויהיה מוצפן
const register = async (req, res) => {
  const user = await User.create({ ...req.body });
  const token = user.createJWT(); // קישור לפונקציה שממירה את השם
  res.status(StatusCodes.CREATED).json({ user: { name: user.name }, token }); // השם יהיה גלוי בפרטים
};

// פונקציה עם תנאים שבודקים אם יש שם מתשמש, מייל וסיסמא
const login = async (req, res) => {
  const { email, password } = req.body;
  // אם אין מייל וסיסמא - הודעת שגיאה
  if (!email || !password) {
    throw new BadRequestError("Please provide email and password");
  }
  // אם המשתמש לא קיים נוסיף משתנה שיהיה שווה להודעת שגיאה
  const user = await User.findOne({ email });
  if (!user) {
    throw new UnauthenticatedError("Invalid Credentials"); //
  }
  // אם יש משתמש אז בדיקה הבאה סיסמא - מכניסים את המשתנה של הפונקציה שבדקהאת ההתאמה בין הסיסמא המוצפנת לזו במסד נתונים
  const isPasswordCorrect = await user.comparePassword(password);
  if (!isPasswordCorrect) {
    throw new UnauthenticatedError("Invalid Credentials");
  }
  // הצפנה
  const token = user.createJWT();
  res.status(StatusCodes.OK).json({ user: { name: user.name }, token });
};

module.exports = {
  register,
  login,
};
