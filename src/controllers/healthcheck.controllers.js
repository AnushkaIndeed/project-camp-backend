import { ApiResponse } from "../utils/api-response.js";
import { asyncHandler } from "../utils/async-handler.js";
 /* const healthCheck = async (req, res, next) => {
    try{
        const user= await getUserFromDB()
        res.status(200).json(
            new ApiResponse(200,{message:"Server is running"})
        );
    
    }
    catch(error) {
        next(err)
    }
}; */ //conventional way is this but we use async handlers to simplify this.

const healthCheck = asyncHandler(async (req,res) => {
    res.status(200)
    .json(new ApiResponse(200, {message:"server is still running"},
        "success"
    ));
});
export {healthCheck};


