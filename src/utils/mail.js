import Mailgen from "mailgen";

import nodemailer from "nodemailer";

const sendEmail = async (options) => {
    const mailGenerator = new Mailgen({
        theme: "default",
        product: {
            name:"task manager",
            link: "https://taskmanagelink.com"
        }
    })

   const emailTextual=  mailGenerator.generatePlaintext(options.mailgenContent)
   const emailHtml=  mailGenerator.generate(options.mailgenContent)

   const transporter = nodemailer.createTransport({
    host: process.env.MAILTRAP_SMTP_HOST,
    port: process.env.MAILTRAP_SMTP_PORT,
    auth:
    {
        user: process.env.MAILTRAP_SMTP_USER,
        pass: process.env.MAILTRAP_SMTP_PASS
    }
   })

   const mail = {
    from:"mail.taskmanager@example.com",
    to: options.email,
    subject: options.subject,
    text: emailTextual,
    html: emailHtml
   }
   try{
    await transporter.sendMail(mail)
   }catch(error){
    console.error("email service failed silently.Make sure that you have provided your MAILTRAP credentials in the .env file");
    console.error("Error:", error)
   }


}

const emailVerificationMailgenContent = (username, verificationUrl) =>
{
    return{
        body:{
            name: username,
            intro: "Welcome to our App! we are excited to have you on board.",
            action:{
                instructions: "To verify your email pleae click on the following button",
                button: {
                color: '#5473e4ff', // Optional action button color
                text: 'Confirm your account',
                link: verificationUrl,
            },
            },
        outro: "Need help, or have questions? Just reply to this email, we\'d love to help.",

        },
    };
};

const forgotPasswordMailgenContent = (username, passwordResetUrl) =>
{
    return{
        body:{
            name: username,
            intro: "We got a request to reset the password of your account",
            action:{
                instructions: "To reset your password click the below given button",
                button: {
                color: '#5a8feaff', // Optional action button color
                text: 'Reset password',
                link: passwordResetUrl,
            },
            },
        outro: "Need help, or have questions? Just reply to this email, we\'d love to help.",

        },
    };
};
export{
    emailVerificationMailgenContent,
    forgotPasswordMailgenContent,
    sendEmail
};
