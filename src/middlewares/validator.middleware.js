import {validationResult} from "express-validator";
import { ApiError } from "../utils/api-error.js";

//reusable
export const validate= (req, res, next) => {
    const errors= validationResult(req)
    if (errors.isEmpty()){
        return next();
    }
    const extractedErrors = [];
    errors.array().map( (err) => extractedErrors.push( { [err.path]: err.msg}));
    //pushing an error path and msg as an object
    throw new ApiError(422, "Recieved data is not valid", extractedErrors);
}
//design of middleware