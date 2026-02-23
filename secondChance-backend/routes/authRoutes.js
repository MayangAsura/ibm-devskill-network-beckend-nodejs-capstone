const express = require('express')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcrypt')
const dotenv = require('dotenv')
const {check, body, validationResult } = require('express-validator')
const logger = require('../logger.js')
// const logger = pino()

dotenv.config()

const connectToDatabase = require('../models/db.js')

const router = express.Router()

router.post('/login', async (req, res) => {
    const {email, password} = req.body

    try {

        const db = await connectToDatabase()

        const collection = await db.collection('users')

        const users = await collection.findOne({email: email})

        if(users){
            const isMatch = await bcrypt.compare(password, users.password)
            
            if(!isMatch){
                logger.error('Email or password wrong.')
                return res.status(400).json({error: 'Email or Password wrong.'})
            }

            const userName = users.firstName
            const userEmail = users.email
    
            const payload = {
                user: {
                    _id: users._id.toString()
                }
            }
            const JWT_SECRET = process.env.JWT_SECRET
            
            const token = jwt.sign(payload, JWT_SECRET, {expiresIn: '24h'})
    
            res.json({token, userName, userEmail})

        }else{
            logger.error('User not found')
            return res.status(404).json({error: 'User not found'})
        }

        
    } catch (error) {
        logger.error('Error when logged in' + error)
        res.status(500).json({error: 'Error when logged in: '+ error})
    }
})

router.post('/register', async (req, res) => {
    
    try {
        const db = await connectToDatabase()
        const collection = await db.collection('users')

        const {email, password, firstName, lastName } = req.body

        const user = await collection.findOne({email: req.body.email})
        if(user){
            logger.error('User already exist')
            return res.status(400).json({error: 'User already exist.'})
        }
        
        const salt = await bcrypt.genSalt(10)
        const hashed_password = await bcrypt.hash(password, salt)

        const data = await collection.insertOne({
            email: email,
            password: hashed_password,
            firstName: firstName,
            lastName: lastName,
            createdAt: new Date().toDateString()
        })

        const JWT_SECRET = process.env.JWT_SECRET
        const payload = {
            user: {
                id: data.insertedId
            }
        }
        const token = jwt.sign(payload, JWT_SECRET, {expiresIn: '24h'})

        logger.info('User successfully registered.')
        res.status(200).json({email: email, token: token})
        
    } catch (error) {
        logger.error('Error when register: ' + error)
        res.status(500).json({error: 'Error when register: ' + error})
    }

})

router.put('/update', 
    [
        check('email').trim().escape().notEmpty().withMessage('Last name is required.').isEmail().withMessage('Please input valid email').custom( async (email) => {
            try {
                const collection = (await connectToDatabase()).collection('users')
                const user = await collection.findOne({email: email})
                if(!user){
                    return Promise.reject('Email not found')
                }
                
            } catch (error) {
                throw error
            }
        }),
        check('firstName').trim().escape().notEmpty().withMessage('First name is required.'),
        check('lastName').trim().escape().notEmpty().withMessage('Last name is required.'),
        check('password').trim().escape().notEmpty().withMessage('Password is required.').isStrongPassword({
            minLength: 8,
            minUppercase: 1,
            minLowercase: 1,
            minSymbols: 0
        }).withMessage("Please ensure your password at least 8 characters long, has at least one uppercase and one lowercase letters"),
        check('confirm_password').trim().escape().notEmpty().withMessage("Confirm passwors is required.").custom(
            (confirmPassword, {req: request}) => confirmPassword== request.body.password
        ).withMessage('The password and its confirm password do not match, please input correctly')
    ],
    async (req, res) => {
    try {
        const {firstName, lastName, password } = req.body

        const errors = validationResult(req)
        if(errors.isEmpty()){
            logger.error('Error validation: ', errors.array())
            return res.status(400).json({error: `Error validation: ${errors.array()}`})
        }

        const email = req.headers.email

        if(!email){
            logger.error('Email not found in the request headers')
            return res.status(400).json({error: 'Please include email in request headers'})
        }
        const collection = await connectToDatabase().collection('users')
        const users = await collection.findOne({email: email})
        const salt = bcrypt.genSalt(10)
        const hash_password = bcrypt.hash(password, salt)
        users.firstName = firstName
        users.lastName = lastName
        users.email = email
        users.password = hash_password
        users.updatedAt = new Date().toDateString()
        
        const updatedUser = await collection.findOneAndUpdate(
            {email},
            {returnDocument: 'after'},
            {$set: users},
        )
        const payload = {
            user: {
                id: updatedUser._id.toString()
            }
        }
        const JWT_SECRET = process.env.JWT_SECRET
        const token = jwt.sign(payload, JWT_SECRET, {expiresIn: '24h'})

        res.status(200).json({message: 'Succesfuly updated profile', token})

    } catch (error) {
        logger.error('Error when update user.')
        return res.status(400).json({error: 'Error when update user.'})
    }
})

module.exports = router