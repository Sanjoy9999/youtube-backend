import { ApiError } from "../utils/ApiError.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import jwt from "jsonwebtoken"
import {User} from "../models/user.model.js"





export const verifyJWT = asyncHandler(async (req, _, next) => {
   try {
     // Try to get the token from the header or cookies
     const token = req.cookies?.accessToken || req
       .header("Authorization")?.replace("Bearer ", "");
   //   console.log("Received Token:", token || "No token provided"); // Debugging



     if (!token) {
         throw new ApiError(401, "Unauthorized request: No token found");
     }


     // Verify token
     const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);

     // Find user
     const user = await User.findById(decodedToken?._id)
       .select("-password -refreshToken");

     if (!user) {
       throw new ApiError(401, "Invalid access token: User not found");
     }

     req.user = user;
     next();

   } catch (error) {
     throw new ApiError(401, error?.message || "Invalid access token");
   }
});


