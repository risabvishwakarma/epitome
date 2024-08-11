import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

interface JwtPayload {
    userId: string;
}

const extractUserId = (req: Request, res: Response, next: NextFunction) => {
        const authHeader = req.headers['authorization'];
        const token = authHeader?.split(' ')[1] ?? req.cookies?.token;

        if (!token) {
            return res.status(401).json({ message: 'Token required' });
        }

        try {
            const decoded = jwt.verify(token, process.env.JWT_SECRET as string) as JwtPayload;
            const { userId } = decoded;

            // Attach the userId to the request object
            (req as any).userId = userId;

            next();
        } catch (err) {
            return res.status(403).json({ message: 'Invalid token' });
        }
    };

export default extractUserId;
