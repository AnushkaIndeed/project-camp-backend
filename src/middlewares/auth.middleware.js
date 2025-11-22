import { User } from "../models/user.models.js";
import { ApiError } from "../utils/api-error.js";
import { asyncHandler } from "../utils/async-handler.js";
import jwt from "jsonwebtoken";
//middleware for verifying jwt

export const verifyJWT = asyncHandler(async(req, res , next) => {
    const authHeader = req.header("Authorization");
    const token = req.cookies?.accessToken ||
    (authHeader && authHeader.startsWith("Bearer ") 
      ? authHeader.split(" ")[1] 
      : null);
     //accessing the AT, .replace is a js method which helps identify and take the bearer token 
     if(!token) {
        throw new ApiError(401, "Unauthorised request");
     }
     try {
        const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET)
        //decodes the token
        const user = await User.findById(decodedToken?._id).select("-password -refreshToken -emailVerificationToken -emailVerificationExpiry" );
        if(!user) {
        throw new ApiError(401, "Invalid access token");
         }
        req.user = user 
        next()

     } catch (error) {
        throw new ApiError(401, "Invalid access token");
     }
})