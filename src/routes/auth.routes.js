import express from "express";
import { changeCurrentPassword, forgotPasswordRequest, getCurrentUser, login , logoutUser, refreshAccessToken, registerUser, resendEmailVerifcation, resetPassword, verifyEmail } from "../controllers/auth.controllers.js";
import { validate } from "../middlewares/validator.middleware.js";
import { userChangeCurrentPasswordValidator, userforgotPasswordValidator, userLogInValidator, userRegisterValidator, userResetForgotPasswordValidator } from "../validators/index.js";
import { verifyJWT } from "../middlewares/auth.middleware.js";

const router = express.Router();


router.route("/register").post(userRegisterValidator(), validate, registerUser);
router.route("/login").post(userLogInValidator(), validate, login);
router.route("/verify-email/:verificationToken").get(verifyEmail);
router.route("/refresh-token").post(refreshAccessToken);
router.route("/forgot-password").post( userforgotPasswordValidator(), validate, forgotPasswordRequest);
router.route("/reset-password/:resetToken").post(userResetForgotPasswordValidator(), validate, resetPassword);
//secure routes
router.route("/logout").post(verifyJWT, logoutUser);
router.route("/current-user").post(verifyJWT, getCurrentUser);
router.route("/change=password").get(verifyJWT, userChangeCurrentPasswordValidator(), validate, changeCurrentPassword);
router.route("/resend-email-verification").post(verifyJWT, resendEmailVerifcation);




export default router;
