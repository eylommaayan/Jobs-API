const Job = require("../models/Job");
const { StatusCodes } = require("http-status-codes");
const { BadRequestError, NotFoundError } = require("../errors");

// פונקציה בשביל להכניס את העבודות למסד
const getAllJobs = async (req, res) => {
  const jobs = await Job.find({ createdBy: req.user.userId }).sort("createdAt");
  res.status(StatusCodes.OK).json({ jobs, count: jobs.length });
};
// פונקציה בשביל עבודה אחת
const getJob = async (req, res) => {
  const {
    user: { userId },
    params: { id: jobId },
  } = req;

  const job = await Job.findOne({
    _id: jobId,
    createdBy: userId,
  });
  if (!job) {
    throw new NotFoundError(`No job with id ${jobId}`);
  }
  res.status(StatusCodes.OK).json({ job });
};

// בשביל להוסיף עבודה חדשה למסד נתונים
const createJob = async (req, res) => {
  req.body.createdBy = req.user.userId; //moderl/job- createdBy  שימוש בפונציה
  const job = await Job.create(req.body);
  res.status(StatusCodes.CREATED).json({ job });
};

// עדכון עבודה
const updateJob = async (req, res) => {
  const {
    // מה שנחפש
    body: { company, position },
    user: { userId },
    params: { id: jobId },
  } = req;
  // אם זה ריק
  if (company === "" || position === "") {
    throw new BadRequestError("Company or Position fields cannot be empty");
  }
  // מה שנרצה לעדכן
  const job = await Job.findByIdAndUpdate(
    { _id: jobId, createdBy: userId },
    req.body,
    { new: true, runValidators: true }
  );
  // אם העבודה החדשה לא קיימת
  if (!job) {
    throw new NotFoundError(`No job with id ${jobId}`);
  }
  res.status(StatusCodes.OK).json({ job });
};

//מחיקת עבודה
const deleteJob = async (req, res) => {
  const {
    user: { userId },
    params: { id: jobId },
  } = req;

  const job = await Job.findByIdAndRemove({
    _id: jobId,
    createdBy: userId,
  });
  if (!job) {
    throw new NotFoundError(`No job with id ${jobId}`);
  }
  res.status(StatusCodes.OK).send();
};

module.exports = {
  getAllJobs,
  getJob,
  createJob,
  updateJob,
  deleteJob,
};
