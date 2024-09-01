import express from 'express';
import UserController from '../controller/UserController'
import authenticateToken from '../middleware/AuthMiddleware';
import authorizeRoles from '../middleware/AuthRoleMiddleware';
import authSubs from '../middleware/AuthSubsctiption';
import extractUserId from '../middleware/ExtractUserId';

const router = express.Router();
const userController = new UserController();

// Authentication routes
router.post('/register', userController.verifyEmail);
router.post('/verification',userController.registerUser)
router.post('/login', userController.loginUser);
router.post('/logout', userController.logoutUser);
router.post('/forgot-password', userController.forgotPassword);
router.post('/reset-password', userController.resetPassword);

router.post('/home',authSubs,extractUserId, userController.home);

router.get('/subscription-status',authenticateToken, authorizeRoles('Admin', 'Client', 'User'),extractUserId, userController.checkSubscriptionStatus);
router.post('/renew-subscription', authenticateToken, authorizeRoles('Admin', 'Client', 'User'),extractUserId, userController.renewSubscription);
router.post('/cancel-subscription', authenticateToken, authorizeRoles('Admin', 'Client', 'User'), authSubs ,extractUserId, userController.cancelSubscription);

router.get('/profile', authenticateToken,extractUserId, userController.profile);

router.get('/admin', authenticateToken, authorizeRoles('Admin'),extractUserId, (req, res) => {
    res.json({ message: 'Welcome Admin' });
});

// Route accessible by Admin and Client
router.get('/client', authenticateToken, authorizeRoles('Admin', 'Client'),extractUserId, (req, res) => {
    res.json({ message: 'Welcome Client' });
});

// Route accessible by Admin, Client, and User
router.get('/user', authenticateToken, authorizeRoles('Admin', 'Client', 'User'),extractUserId, (req, res) => {
    res.json({ message: 'Welcome User' });
});



export default router;
