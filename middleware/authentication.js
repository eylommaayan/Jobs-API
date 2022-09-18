const User = require("../models/User");
const jwt = require("jsonwebtoken"); // משיכת ספרייה
const { UnauthenticatedError } = require("../errors");

//פונקצית נקודת אמצע
const auth = async (req, res, next) => {
  // check header
  const authHeader = req.headers.authorization;
  // -schema bearer אם זה לא קיים או אם לא מתחיל עם
  if (!authHeader || !authHeader.startsWith("Bearer")) {
    throw new UnauthenticatedError("Authentication invalid");
  }
  // להפוך את המשתנה למחוזרת ולבדוק את החלק השני במחוזרת - [1]
  const token = authHeader.split(" ")[1];

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    // attach the user to the job routes
    req.user = { userId: payload.userId, name: payload.name };
    next();
  } catch (error) {
    throw new UnauthenticatedError("Authentication invalid");
  }
};

module.exports = auth;
