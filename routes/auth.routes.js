const express = require('express')
const bcrypt = require('bcrypt')
const User = require('../models/User.model')
const router = express.Router()


router.get('/signup', (req, res) => {
    res.render('auth/signup')
  })

  router.get('/userProfile', (req, res) => {
     
    res.render('users/user-profile', { user: req.session.user })
  })



router.post('/signup', async (req, res) => {
    const body = { ...req.body }

    if (body.password.length === 0 || body.username.length === 0){
        res.render('auth/signup', { errorMessage: 'Field cannot be empty', body: req.body })
    }else{
    const salt = bcrypt.genSaltSync(13)
    const passwordHash = bcrypt.hashSync(body.password, salt)
    console.log(passwordHash)

    delete body.password
    body.passwordHash = passwordHash

    try {
        await User.create(body)
        //res.send(body)
        res.redirect('/userProfile');
      } catch (error) {
        if (error.code === 11000) {
          console.log('Duplicate !')
          res.render('auth/signup', {
            errorMessage: 'Username already used !',
            userData: req.body,
          })
        } else {
          res.render('auth/signup', {
            errorMessage: error,
            userData: req.body,
          })
        }
      }
    } 
})


router.get('/login', (req, res) => {
    res.render('auth/login')
  })

router.post('/login', async (req, res) => {
    const body = req.body
  
    const userMatch = await User.find({ username: body.username })
    // console.log(userMatch)
    if (userMatch.length) {
      // User found
      const user = userMatch[0]
  
      if (bcrypt.compareSync(body.password, user.passwordHash)) {
        // Correct password
  
        const tempUser = {
          username: user.username,
          email: user.email,
        }
  
        req.session.user = tempUser
        res.redirect('/userProfile');
      } else {
        res.render('auth/login', { errorMessage: 'Incorrect password.' });
      }
    } else {
        res.render('auth/login', { errorMessage: 'User not found.' });
    }
  })

  module.exports = router
