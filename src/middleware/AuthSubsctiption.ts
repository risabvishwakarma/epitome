import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import User from '../models/UserModel';

interface JwtPayload {
    userId: string;
}

const authSubs = async (req: Request, res: Response, next: NextFunction) => {
        try {
            const authHeader = req.headers['authorization'];
            const token = authHeader?.split(' ')[1] ?? req.cookies?.token;

            if (!token) {
                return res.status(401).json({ message: 'Token required' });
            }

            const decoded = jwt.verify(token, process.env.JWT_SECRET as string) as JwtPayload;
            const { userId } = decoded;

            console.log("Decoded email:", userId);

            // Fetch the user from the database using email
            const user = await User.findById(userId);
            if (!user) {
                return res.status(404).json({ message: 'User not found' });
            }

            console.log("User found:", user);

            // Check if the user has an active subscription
            if (!user.haveSubscription) {  // Corrected typo here
                return res.status(403).json({ message: 'Subscription not active' });
            }

            console.log("User has an active subscription");

            // Check if the subscriptionExpiry exists and is still valid
            if (user.subscriptionExpiry && new Date(user.subscriptionExpiry).getTime() < Date.now()) {
                return res.status(403).json({ message: 'Subscription expired' });
            }

            console.log("Subscription is valid");

            // Attach user info to the request object for later middleware or route handlers
            (req as any).user = user;
            next();
        } catch (err) {
            console.error("Error in authSubs middleware:", err);
            // Pass the error to the next middleware, which can handle it or return an error response
            return res.status(403).json({ message: 'Invalid token or internal error' });
        }
    };

export default authSubs;
