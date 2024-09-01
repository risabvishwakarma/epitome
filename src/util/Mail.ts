import nodemailer from 'nodemailer';

class UserService {
    // Other methods...

    public async sendEmail(email: string, msg: string, subject: string): Promise<void> {
        try {
            console.log(`Sending email to ${email} with subject: ${subject}`);

            const transporter = nodemailer.createTransport({
                service: 'Gmail', // or another email service
                auth: {
                    user: process.env.EMAIL_USER,
                    pass: process.env.EMAIL_PASS,
                },
            });

            const mailOptions = {
                to: email,
                from: process.env.EMAIL_USER,
                subject: subject,
                text: msg,
            };

            await transporter.sendMail(mailOptions);
            console.log('Email sent successfully');
        } catch (error) {
            console.error(`Error sending email: ${error}`);
            throw new Error('Failed to send email');
        }
    }
}

export default UserService;
