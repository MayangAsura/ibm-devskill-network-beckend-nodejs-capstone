const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const router = express.Router();
const connectToDatabase = require('../models/db');
const logger = require('../logger');

// Define the upload directory path
const directoryPath = 'public/images';

// Set up storage for uploaded files
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, directoryPath); // Specify the upload directory
  },
  filename: function (req, file, cb) {
    cb(null, file.originalname); // Use the original file name
  },
});

const upload = multer({ storage: storage });


// Get all secondChanceItems
router.get('/', async (req, res, next) => {
    logger.info('/ called');
    try {
        //Step 2: task 1 - insert code here
        const db = await connectToDatabase()
        //Step 2: task 2 - insert code here
        const collection = await db.collection('secondChanceItems')
        //Step 2: task 3 - insert code here
        const secondChanceItem = await collection.find().toArray()
        //Step 2: task 4 - insert code here
        return secondChanceItem

        // const collection = db.collection("secondChanceItems");
        // const secondChanceItems = await collection.find({}).toArray();
        // res.json(secondChanceItems);
    } catch (e) {
        logger.console.error('oops something went wrong', e)
        next(e);
    }
});

// Add a new item
router.post('/', {Step 3: Task 6 insert code here}, async(req, res,next) => {
    try {
        //Step 3: task 1 - insert code here
        const db = await connectToDatabase()
        //Step 3: task 2 - insert code here
        const collection = await db.collection('secondChanceItems')
        //Step 3: task 3 - insert code here
        const data = req.body
        //Step 3: task 4 - insert code here
        const secondChanceItem = await collection.find().sort({id: -id}).limit(1)
        data.id = parseInt(secondChanceItem.id) + 1
        //Step 3: task 5 - insert code here
        data.date = new Date().toDateString()

        await data.save()
        res.status(201).json(secondChanceItem.ops[0]);
    } catch (e) {
        next(e);
    }
});

// Get a single secondChanceItem by ID
router.get('/:id', async (req, res, next) => {
    try {
        //Step 4: task 1 - insert code here
        const db = await connectToDatabase()
        //Step 4: task 2 - insert code here
        const collection = await db.collection('secondChaceItems')
        //Step 4: task 3 - insert code here
        const secondChanceItem = await collection.find({id: req.params.id})
        //Step 4: task 4 - insert code here
        if(!secondChanceItem){
            return res.json({message: "Item not found"})
        }
        return secondChanceItem
    } catch (e) {
        next(e);
    }
});

// Update and existing item
router.put('/:id', async(req, res,next) => {
    try {
        //Step 5: task 1 - insert code here
        const db = await connectToDatabase()
        //Step 5: task 2 - insert code here
        const collection = await db.collection('secondChanceItems')
        //Step 5: task 3 - insert code here
        const secondChanceItem = await collection.find({id: req.params.id})
        if(!secondChanceItem){
            return res.status(400).json({message: 'Item not found'})
        }
        //Step 5: task 4 - insert code here
        secondChanceItem.category = req.body.category
        secondChanceItem.condition = req.body.condition
        secondChanceItem.age_days = req.body.age_days
        secondChanceItem.description = req.body.description
        secondChanceItem.age_years = Number(secondChanceItem.age_days/365).toFixed(1)
        secondChanceItem.updatedAt = new Date().toDateString()

        const data = await collection.findOneAndUpdate(
            {id: req.params.id},
            {$set: secondChanceItem},
            {returnDocument: 'after'}
        )

        //Step 5: task 5 - insert code here
        if(data){
            res.json({message: 'Updated successfully'})
        }else{
            res.json({message: 'Updated failed'})
        }
      
    } catch (e) {
        next(e);
    }
});

// Delete an existing item
router.delete('/:id', async(req, res,next) => {
    try {
        //Step 6: task 1 - insert code here
        //Step 6: task 2 - insert code here
        //Step 6: task 3 - insert code here
        //Step 6: task 4 - insert code here
    } catch (e) {
        next(e);
    }
});

module.exports = router;
