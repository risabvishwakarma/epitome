import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

const authenticateToken = (req: Request, res: Response, next: NextFunction): void => {
    const authHeader = req.headers['authorization'];
    const token = authHeader?.split(' ')[1] ?? req.cookies?.token;

    console.log(token)

    if (!token) {
        res.status(401).json({ message: 'Token required' });
        return;
    }

    jwt.verify(token, process.env.JWT_SECRET as string, (err: any, decoded: any) => {
        if (err) {
            res.status(403).json({ message: 'Invalid token' });
            return;
        }

        (req as any).user = decoded;
        next();
    });
};

export default authenticateToken;
