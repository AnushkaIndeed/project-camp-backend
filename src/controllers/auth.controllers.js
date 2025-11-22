import {User} from "../models/user.models.js";
import { ApiResponse } from "../utils/api-response.js";
import { ApiError } from "../utils/api-error.js";
import { asyncHandler } from "../utils/async-handler.js";
import { emailVerificationMailgenContent, forgotPasswordMailgenContent, sendEmail } from "../utils/mail.js";
import jwt from "jsonwebtoken";


const generateAccessAndRefreshTokens = async (UserId) => {
    try {
        const user = await User.findById(UserId);
        const accessToken= user.generateAccessToken();
        const refreshToken =user.generateRefreshToken();
        user.refreshToken= refreshToken //we can save this refresh token in the db as RT is a field in db
        await user.save({validateBeforeSave: false})
        return { accessToken, refreshToken}

    } catch (error) {
        throw new ApiError(500, "something went wrong while generating access token")
    }
}
//main code for registering user
const registerUser= asyncHandler(async(req,res) => {
   const {email, username, password, role} = req.body
   const existingUser = await User.findOne({
    $or: [{username}, {email}]
   })
   if (existingUser){
    throw new ApiError(409, "user with same username and email already exists! ")
   }
   const user = await User.create({
    email, password, username, isEmailVerified: false
   })
   const {unHashedToken, hashedToken, tokenExpiry} = user.generateTemporaryToken();

   user.emailVerificationToken= hashedToken;
   user.emailVerificationExpiry= tokenExpiry;
   await user.save({validateBeforeSave: false});

    //send token to the user
    await sendEmail(
        {
            email: user?.email,
            subject:"Please verify your email",
            mailgenContent: emailVerificationMailgenContent
            (
                user.username, 
                `${req.protocol}://${req.get("host")}/api/v1/users/verify-email/${unHashedToken}`
                //this is a url that a user clicks and controllers and routes will be created for verify emailwhich takes unhashed token and processes this (dynamic link)

            ),
        }
    );

    const createdUser= await User.findById(user._id).select(
        "-password -refreshToken -emailVerificationToken -emailVerificationExpiry" 
    ); //the - is used to remove/hide the content used with it

    if(!createdUser){
        throw new ApiError(500, "something went user while registering the user")
    };

    return res
    .status(201)
    .json(new ApiResponse(200,{user: createdUser},"User registered successfully and verification email has been sent to your email"

    ))

});

//user login code
const login = asyncHandler(async (req,res) => {
    const {email, password, username} = req.body
    if(!email){
        throw new ApiError(400, "Email is required");
    }
    const user = await User.findOne({email});
    if(!user){
        throw new ApiError(400, "user does not exists");
    }
    const isPasswordValid= await user.isPasswordCorrect(password);
    if(!isPasswordValid){
        throw new ApiError(400, "invalid credentials");
    }
    const {accessToken, refreshToken} = await generateAccessAndRefreshTokens(user._id);

    const loggedInUser= await User.findById(user._id).select(
        "-password -refreshToken -emailVerificationToken -emailVerificationExpiry" 
    ); //the - is used to remove/hide the content used with it

    const options = {
        httpOnly: true,
        //Protects from XSS attacks (Cross-Site Scripting).The cookie cannot be accessed by JavaScript on the browser (not accessible via document.cookie).
        secure: true 
        //Cookie will only be sent over HTTPS (not HTTP).Ensures encrypted communication.
        //cookies that only the browser can manipulate
    }
    return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json( new ApiResponse(200, {
        user: loggedInUser,
        accessToken, 
        refreshToken
    },
    "User logged in successfully"

))

   




});

//logout of user code
const logoutUser = asyncHandler(async(req , res) => {
    await User.findByIdAndUpdate(
        req.user._id,
        {
            $set : {
                refreshToken: "",
            },
        },
        {
            new: true
        },
    );
    const options = {
        httpOnly: true,
        secure: true
    }
    return res 
    .status(200)
    .clearCookie("accessToken",options)
    .clearCookie("refreshToken",options)
    .json(
        new ApiResponse(200, {} , "User logged out")
    );

});

const getCurrentUser = asyncHandler(async(req , res) => {
    return res
    .status(200)
    .json(new ApiResponse(200, req.user, "Current user fetched successfully"));

});

const verifyEmail = asyncHandler(async(req,res) => {
    const {verificationToken}= req.params;
    if(!verificationToken){
     throw new ApiError(400, "email verification token is missing");
    }
    let hashedToken = crypto
     .createHash("sha256")
     .update(verificationToken)
     .digest("hex")
    
    const user = await User.findOne({
        emailVerificationToken: hashedToken,
        emailVerificationExpiry: {$gt : Date.now()}
        //  condition is written in {} that $ (this) field is greater than now
    })
    if(!user){
        throw new ApiError(400, "Token is Invalid or expired ");  

    }

    user.emailVerificationToken = undefined;
    user.emailVerificationExpiry = undefined; //for cleanup of unncessary data

    user.isEmailVerified = true;
    await user.save({validateBeforeSave: false});

    return res
    .status(200)
    .json(new ApiResponse(200, { isEmailVerified:true}, "email is verified"))
});

const resendEmailVerifcation = asyncHandler (async(req,res) => {
    //req.user?._id done by jwt then the below works 
    const user = await User.findById(req.user?._id);
    if(!user){
        throw new ApiError(404, "User does not exist");
    }
    if(user.isEmailVerified){
        throw new ApiError(409, "Email is already verified")
    };

//resend email verification same steps as done while registering the user
   const {unHashedToken, hashedToken, tokenExpiry} = user.generateTemporaryToken();
   user.emailVerificationToken= hashedToken;
   user.emailVerificationExpiry= tokenExpiry;
   await user.save({validateBeforeSave: false});

    //send token to the user
    await sendEmail(
        {
            email: user?.email,
            subject:"Please verify your email",
            mailgenContent: emailVerificationMailgenContent
            (
                user.username, 
                `${req.protocol}://${req.get("host")}/api/v1/users/verify-email/${unHashedToken}`
                //this is a url that a user clicks and controllers and routes will be created for verify emailwhich takes unhashed token and processes this (dynamic link)

            ),
        }
    );
    return res
    .status(200)
    .json(new ApiResponse(200, {} , "Mail has been send to your email"))


});

const refreshAccessToken = asyncHandler(async(req , res) => {
    const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken
    if(!incomingRefreshToken){
        throw new ApiError(401, "Unauthorised access")
    }
    try {
        const decodedToken= jwt.verify(incomingRefreshToken, process.env.REFRESH_TOKEN_SECRET);
        const user = await User.findById(decodedToken?._id);
        if(!user){throw new ApiError(401, "Invalid Refresh Token");}
        if(incomingRefreshToken !== user.refreshToken){
            throw new ApiError(401, "refresh token is expired");
        }

        const options ={
            httpOnly: true,
            secure: process.env.NODE_ENV === "production"

        }
        const {accessToken, refreshToken: newRefreshToken} =  await generateAccessAndRefreshTokens(user._id)
        user.refreshToken= newRefreshToken;
        await user.save()
        return res 
         .status(200)
         .cookie("accessToken", accessToken, options)
         .cookie("refreshToken", newRefreshToken, options)
         .json( new ApiResponse(200, { accessToken, refreshToken: newRefreshToken}, "access token is refreshed"))
    } catch (error) {

        throw new ApiError(401, "Invalid refresh token");
    }
})
const forgotPasswordRequest = asyncHandler(async(req , res) => {
    const {email} = req.body 
    const user = await User.findOne({email})
    if(!user){
        throw new ApiError (404, "user does not exist", [])
    } 
    const {unHashedToken, hashedToken, tokenExpiry}= user.generateTemporaryToken();
    user.forgotPasswordToken= hashedToken;
    user.forgotPasswordExpiry=tokenExpiry;
    await user.save({validateBeforeSave: false})
    await sendEmail({
            email: user?.email,
            subject:"Password reset request ",
            mailgenContent: forgotPasswordMailgenContent
            (
                user.username, 
                // `${req.protocol}://${req.get("host")}/api/v1/users/verify-email/${unHashedToken}`, either use this or likenow use fixed redirecting path described in .env file
                `${process.env.FORGOT_PASSWORD_REDIRECT_URL}/${unHashedToken}`,
                

            ),
        }
    );

    return res
    .status(200)
    .json(new ApiResponse(200, {}, "password reset mail has been sent to your email"));
})
const resetPassword = asyncHandler(async(req , res) => {
   const {resetToken} = req.params
   const {newPassword} = req.body
   let hashedToken = crypto.createHash("sha256").update(resetToken).digest("hex")
   const user =  await User.findOne({
    forgotPasswordToken: hashedToken,
    forgotPasswordExpiry:{$gt :Date.now()}

   })
   if(!user){
    throw new ApiError(400, "token is invalid or expired")
   }
   user.forgotPasswordExpiry=undefined;
   user.forgotPasswordToken= undefined;
   user.password = newPassword
   await user.save({ validateBeforeSave: false})

   return res 
   .status(200)
   .json(new ApiResponse(200, {} , "password reset successfully"));
})

//user is logged in while changing the password 
const changeCurrentPassword = asyncHandler(async(req , res) => {
    const {oldPassword, newPassword} = req.body
    const user =  await User.findById(req.user?._id);

    const isPasswordValid= await user.isPasswordCorrect(oldPassword);

    if(!isPasswordValid){
        throw new ApiError(400, "Invalid Old Password")
    }

    user.password= newPassword
    await user.save({validateBeforeSave: false})

    return res
   .status(200)
   .json(new ApiResponse(200, {} , "password changed successfully"));
})

export { registerUser, login, logoutUser, getCurrentUser, verifyEmail, refreshAccessToken, forgotPasswordRequest, changeCurrentPassword, resetPassword, resendEmailVerifcation}; 