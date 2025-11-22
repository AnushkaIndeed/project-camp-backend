import {body} from "express-validator";
const userRegisterValidator = () => {
    return [
        body("email")
        //using methods to validate before
         .trim()
         .notEmpty()
         .withMessage("email is required")
         .isEmail()
         .withMessage("email is invalid"),
        body("username")
         .trim()
         .notEmpty()
         .withMessage("username is required")
         .isLowercase()
         .withMessage("username must be in lowercase")
         .isLength({min:3})
         .withMessage("username must be 3 characters long"),
        body("password")
         .trim()
         .notEmpty()
         .withMessage("password is required"),
        body("fullname")
        .optional()
        .trim()
        //validation done
         

    

    ]
};


const userLogInValidator = () => {
    return [
        body("email")
        .optional()
        .isEmail()
        .withMessage("Invalid Email"),
        body("password")
        .notEmpty()
        .withMessage("Password is required")
    ]
};

const userChangeCurrentPasswordValidator=() => {
    return[
        body("oldPassword")
         .notEmpty()
         .withMessage("Old Password is required"),
        body("newPassword")
         .notEmpty()
         .withMessage("new Password is required"),
         

    ];
};
const userforgotPasswordValidator=() => {
    return[
        body("email")
         .trim()
         .notEmpty()
         .withMessage("email is required")
         .isEmail()
         .withMessage("email is invalid"),
    ];

}
const userResetForgotPasswordValidator=() => {
    return[
        body("newPassword")
         .notEmpty()
         .withMessage("new Password is required")
    ];
}
/*const userChangeCurrentPasswordValidator=() => {
    return{
        
    }
}*/

export{
    userRegisterValidator, userLogInValidator, userChangeCurrentPasswordValidator, userforgotPasswordValidator, userResetForgotPasswordValidator
};