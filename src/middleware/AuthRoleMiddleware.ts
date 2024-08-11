import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import User from '../models/UserModel';

interface JwtPayload {
    userId: string;
    role: string;
}

const authorizeRoles = (...roles: string[]) => {
    return (req: Request, res: Response, next: NextFunction) => {
        const authHeader = req.headers['authorization'];
        const token = authHeader?.split(' ')[1] ?? req.cookies?.token;

        if (!token) {
            return res.status(401).json({ message: 'Token required' });
        }

        jwt.verify(token, process.env.JWT_SECRET as string, async (err:any, decoded:any) => {
            if (err) {
                return res.status(403).json({ message: 'Invalid token' });
            }

            const { role ,userId } = decoded as JwtPayload;

            if (!roles.includes(role)) {
                return res.status(403).json({ message: 'Access denied' });
            }



            (req as any).user = decoded;
            next();
        });
    };
};

export default authorizeRoles;
