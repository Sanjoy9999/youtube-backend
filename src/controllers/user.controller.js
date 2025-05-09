import mongoose from "mongoose"
import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { User } from "../models/user.model.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";


const generateAccessAndRefreshTokens = async (userId) => {
  try {
    const user = await User.findById(userId);
    const accessToken = user.generateAccessToken();
    const refreshToken = user.generateRefreshToken();

    user.refreshToken = refreshToken;
    await user.save({ validateBeforeSave: false });

    return { accessToken, refreshToken };
  } catch (error) {
    throw new ApiError(
      500,
      "Something went wrong while generating refresh and access token"
    );
  }
};

const registerUser = asyncHandler(async (req, res) => {
  // get user details from frontend
  // validation - not empty
  // check if user already exists: username, email
  // check for images,check for avatar
  // upload them to cloudinary , avatar
  // create user object - create entry in db
  // remove password and refresh token field from response
  // check for user creation
  // return res

  const { fullName, email, username, password } = req.body;
  // console.log("email",email);
  console.log("Received request body:", req.body);


  if (
    [fullName, email, username, password].some((field) => field?.trim() === "")
  ) {
    throw new ApiError(400, "All fields are required");
  }

  const exitedUser = await User.findOne({
    $or: [{ username }, { email }],
  });

  if (exitedUser) {
    throw new ApiError(409, "User with email  or username already exits");
  }

  // console.log(req.files);

  const avatarLocalPath = req.files?.avatar[0]?.path;
  // const coverImageLocalPath = req.files?.coverImage[0]?.path;

  let coverImageLocalPath;
  if (
    req.files &&
    Array.isArray(req.files.coverImage) &&
    req.files.coverImage.length > 0
  ) {
    coverImageLocalPath = req.files.coverImage[0].path;
  }

  if (!avatarLocalPath) {
    throw new ApiError(400, "Avatar file is required");
  }

  const avatar = await uploadOnCloudinary(avatarLocalPath);
  const coverImage = await uploadOnCloudinary(coverImageLocalPath);

  if (!avatar) {
    throw new ApiError(400, "Avatar file is required");
  }

  const user = await User.create({
    fullName,
    avatar: avatar.url,
    coverImage: coverImage?.url || "",
    email,
    password,
    username: username.toLowerCase(),
  });

  const createdUser = await User.findById(user._id).select(
    "-password -refreshToken"
  );

  if (!createdUser) {
    throw new ApiError(500, "Something went wrong while registered the user");
  }

  return res
    .status(201)
    .json(new ApiResponse(200, createdUser, "User registered successfully"));
});

const loginUser = asyncHandler(async (req, res) => {
  // req body -> data
  // username or email
  // find the user
  // password check
  // access and refresh Token
  // send cookie

  const { email, username, password } = req.body;
  console.log(email);

  if (!username && !email) {
    throw new ApiError(400, "username or email is required");
  }

  // Here is an alternative of above code based om logic discuss
  // if (!(username || email)) {
  //     throw new ApiError(400,"username or email is required")
  // }

  const user = await User.findOne({
    $or: [{ username }, { email }],
  });

  if (!user) {
    throw new ApiError(404, "User doesn't exist");
  }

  const isPasswordValid = await user.isPasswordCorrect(password);

  if (!isPasswordValid) {
    throw new ApiError(401, "Invalid user passwords");
  }

  const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(
    user._id
  );

  const loggedInUser = await User.findById(user._id).select(
    "-password -refreshToken"
  );
  //   console.log(loggedInUser)

  const options = {
    httpOnly: true,
    secure: true,
  };

  return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
      new ApiResponse(
        200,
        {
          user: loggedInUser,
          accessToken,
          refreshToken,
        },
        "User logged In Successfully"
      )
    );

  const logoutUser = asyncHandler(async (req, res) => {});
});

const logoutUser = asyncHandler(async (req, res) => {
  await User.findByIdAndUpdate(
    req.user._id,
    {
      $unset: {
        refreshToken: 1 //this removes the field from document
      },
    },
    {
      new: true,
    }
  );

  const options = {
    httpOnly: true,
    secure: true,
  };

  return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new ApiResponse(200, {}, "User logged out"));
});

const refreshAccessToken = asyncHandler(async (req, res) => {
  const incomingRefreshToken =
    req.cookies.refreshToken || req.body.refreshToken;

  if (!incomingRefreshToken) {
    throw new ApiError(401, "unauthorized request");
  }

  try {
    const decodedToken = jwt.verify(
      incomingRefreshToken,
      process.env.REFRESH_TOKEN_SECRET
    );

    const user = await User.findById(decodedToken?._id);

    if (!user) {
      throw new ApiError(401, "Invalid refresh token");
    }

    if (incomingRefreshToken !== user?.refreshToken) {
      throw new ApiError(401, "Refresh token is expired or used");
    }

    const options = {
      httpOnly: true,
      secure: true,
    };

    const { accessToken, newRefreshToken } =
      await generateAccessAndRefreshTokens(user._id);

    return res
      .status(200)
      .cookie("accessToken", accessToken, options)
      .cookie("refreshToken", newRefreshToken, options)
      .json(
        new ApiResponse(
          200,
          { accessToken, refreshToken: newRefreshToken },
          "Access token refreshed"
        )
      );
  } catch (error) {
    throw new ApiError(401, error?.message || "Invalid refresh token");
  }
});

const changeCurrentPassword = asyncHandler(async (req, res) => {
  const { oldPassword, newPassword } = req.body;

  //  Validate request body
  if (!oldPassword || !newPassword) {
    throw new ApiError(400, "Both old and new passwords are required");
  }

  //  Find user and ensure password field is selected
  const user = await User.findById(req.user?._id).select("+password");

  if (!user) {
    throw new ApiError(404, "User not found");
  }

  //  Ensure user has a password set
  if (!user.password) {
    throw new ApiError(500, "User password is missing in the database");
  }

  //  Compare old password
  const isPasswordCorrect = await user.isPasswordCorrect(oldPassword);
  if (!isPasswordCorrect) {
    throw new ApiError(400, "Invalid old password");
  }

  //  Hash the new password before saving
  user.password = await bcrypt.hash(newPassword, 10);
  await user.save();  //  Do not disable validation

  return res
    .status(200)
    .json(new ApiResponse(200, {}, "Password changed successfully"));
});




const getCurrentUser = asyncHandler(async (req, res) => {
  return res
  .status(200)
  .json(new ApiResponse(200 , req.user, "current user fetch successfully"));
});



const updateAccountDetails = asyncHandler(async (req, res) => {
  const { fullName, email } = req.body;

  if (!fullName || !email) {
    throw new ApiError(400, "All fields are required");
  }

  const user = await  User.findByIdAndUpdate(
    req.user?._id,
    {
      $set: {
        fullName,
        email,
      },
    },
    { new: true }
  ).select("-password");


  return res
  .status(200)
  .json(new ApiResponse(200,user,"Account details updated successfully"))
});


const updateUserAvatar = asyncHandler(async(req,res)=>{
    
   const avatarLocalPath =  req.file.path

   if (!avatarLocalPath) {
      throw new ApiError(400,"Avatar file is missing")
   }

   //TODO: delete old image - assignment after new avar image upload


   const avatar = await uploadOnCloudinary(avatarLocalPath)

   if (!avatar.url) {
    throw new ApiError(400,"Error while uploading on avatar")
    
   }

  const user =  await User.findByIdAndUpdate(
    req.user?._id,
    {
        $set:{
            avatar: avatar.url 
        }
    },
    {new: true}
   ).select("-password")

   return res
   .status(200)
   .json(
    new ApiResponse(200,user,"Avatar image updated successfully")
   )
})



//TODO: delete old image - assignment after new avar image upload
//for deletion todo above function instead blow to function 



// const updateUserAvatar = asyncHandler(async (req, res) => {
//   if (!req.file) {
//       throw new ApiError(400, "Avatar file is missing");
//   }

//   const avatarLocalPath = req.file.path;

//   // Retrieve existing user to check old avatar
//   const existingUser = await User.findById(req.user?._id);
//   if (!existingUser) {
//       throw new ApiError(404, "User not found");
//   }

//   try {
//       // Upload new avatar to Cloudinary
//       const avatar = await uploadOnCloudinary(avatarLocalPath);
//       if (!avatar?.url) {
//           throw new ApiError(400, "Error while uploading avatar");
//       }

//       // Delete old avatar from Cloudinary (if it exists)
//       if (existingUser.avatar) {
//           await deleteFromCloudinary(existingUser.avatar);
//       }

//       // Update database with new avatar URL
//       existingUser.avatar = avatar.url;
//       await existingUser.save(); // Automatically updates the database

//       return res.status(200).json(
//           new ApiResponse(200, existingUser, "Avatar image updated successfully")
//       );

//   } catch (error) {
//       throw new ApiError(500, "Server error while updating avatar");
//   }
// });



// const deleteFromCloudinary = async (imageUrl) => {
//   if (!imageUrl) return;

//   // Extract publicId from the Cloudinary image URL
//   const publicId = imageUrl.split("/").pop().split(".")[0]; 
//   await cloudinary.uploader.destroy(publicId);
// };




const updateUserCoverImage = asyncHandler(async(req,res)=>{

   const coverImageLocalPath =  req.file.path

   if (!coverImageLocalPath) {
      throw new ApiError(400,"Cover image file is missing")
   }

   const coverImage = await uploadOnCloudinary(coverImageLocalPath)

   if (!coverImage.url) {
    throw new ApiError(400,"Error while uploading on cover image")
    
   }

 const user =   await User.findByIdAndUpdate(
    req.user?._id,
    {
        $set:{
           coverImage: coverImage.url 
        }
    },
    {new: true}
   ).select("-password")

   return res
   .status(200)
   .json(
    new ApiResponse(200,user,"Cover image updated successfully")
   )
})



const getUserChannelProfile = asyncHandler(async (req,res)=>{
   const {username} =  req.params 

   if (!username?.trim()) {
      throw new ApiError(400,"username is missing")
   }

 const channel =  await User.aggregate([
  {
     $match: {
      username: username?.toLowerCase()
     }
  },{
    $lookup: {
       from: "subscriptions",
       localField: "_id",
       foreignField: "channel",
       as: "subscribers"
    }
  },
  {
     $lookup: {
      from: "subscriptions",
      localField: "_id",
      foreignField: "subscriber",
      as: "subscribedTo"
     }
  },
  {
    $addFields: {
       subscribersCount:{
        $size: "$subscribers"
       },
       channelsSubscribedToCount: {
           $size: "$subscribedTo"
       },
       isSubscribed: {
        $cond: {
          if: { $in: [req.user?._id, "$subscribers.subscriber"] },
          then: true,
          else: false
        }   
       }
    }
  },{
     $project: {
       fullName: 1,
       username: 1,
       subscribersCount: 1,  
       channelsSubscribedToCount: 1,
       isSubscribed: 1,
       avatar: 1,
       coverImage: 1,
       email: 1  
     }
  }

 ])


 if (!channel?.length) {
    throw new ApiError(404,"channel does not exists")
 }

 return res
 .status(200)
 .json(
  new ApiResponse(200,channel[0],"User Channel fetched successfully")
 )
})



const getWatchHistory = asyncHandler(async (req,res) => {
   const user = await User.aggregate([
    {
      $match: {
        _id: new mongoose.Types.ObjectId(req.user._id)
      }
    },
    {
       $lookup: {
         from: "videos",
         localField: "watchHistory",
         foreignField: "_id",
         as: "watchHistory",
         pipeline: [
           {
            $lookup: {
              from: "users",
              localField: "owner",
              foreignField: "_id",
              as: "owner",
              pipeline: [
                {
                  $project:{
                    fullName: 1,
                    username: 1,
                    avatar: 1
                  }
                }
              ]
            }
           },
           {
              $addFields:{
                owner: {
                  $first: "$owner"
                }
              }
           }
         ] 
       }
    }
   ])

   return res
   .status(200)
   .json(
    new ApiResponse(
      200,
      user[0].watchHistory,
      "Watch history fetched successfully"
    )
   )
})



export {
  registerUser,
  loginUser,
  logoutUser,
  refreshAccessToken,
  changeCurrentPassword,
  getCurrentUser,
  updateAccountDetails,
  updateUserAvatar,
  updateUserCoverImage,
  getUserChannelProfile,
  getWatchHistory 
};
