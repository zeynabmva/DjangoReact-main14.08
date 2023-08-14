import { useEffect } from "react";
import { CiCircleRemove } from "react-icons/ci";
import React from "react";
 

import { useState } from "react";
const RegistrationModal = ({
  handleSignUpExit,
   
}) => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [passwordConfirm, setPasswordConfirm] = useState('')
  const [registrationSuccess, setRegistrationSuccess] = useState(false);
  const [image, setImage] = useState('/static/reg1.jpg')
 
  const handleSubmit = (event) => {
    event.preventDefault();
 
    const registrationData = {
      email: email,
      password: password,
      passwordConfirm: passwordConfirm,
    };
    fetch('http://127.0.0.1:8000/api/accounts/register/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(registrationData)
    })
      .then(response => response.json())
      .then(data => {
        // Handle API response (success or error)
         
        setRegistrationSuccess(true);
        setImage('/static/check-email.jpg')
      })
      .catch(error => {
        // Handle error
        console.error('Registration error:', error);
        setRegistrationSuccess(false)
      });
  }


  return (
    <div className="login-wrapper">
      <div className="login-input">
        {registrationSuccess ? ( // If registration was successful
        
          <div className="registration-success">
            <h2 className="h4 regis-succ">Email Confirmation.</h2>
            <p className="p">Thank you for signing up with Organick! We hope you'll enjoy your shopping with us.<br></br>Check your email, please. We've sent a message.</p>
           
          </div>
        ) : ( // If registration form is still being shown
          <form method="post" onSubmit={handleSubmit}>
          
            <div className="login-input-head">
              <div className="org">Registration</div>
              <div className="login-input-head-title">
                <p>Welcome Back</p>
                <p className="p login_p">Sign up with your email address and password</p>
              </div>
            </div>
            
            <div className="login-input-title">

              <div className="registr_email">
                <label htmlFor="email">Enter your email</label>
                <input
                  onChange={(e) => setEmail(e.target.value)}
                  id="email"
                  name="email"
                  value={email}
                  type="email"
                  placeholder="Enter your email..."
                />
              </div>

              <div>
                <label htmlFor="password">Create your password</label>
                <input
                  id="password"
                  onChange={(e) => setPassword(e.target.value)}
                  name="password"
                  value={password}
                  type="password"
                  placeholder="Create your password..."
                />
              </div>

              <div>
                <label htmlFor="passwordConfirm">Confirm your password</label>
                <input
                  onChange={(e) => setPasswordConfirm(e.target.value)}
                  id="passwordConfirm"
                  name="password"
                  value={passwordConfirm}
                  type="password"
                  placeholder="Confirm Password"
                />
              </div>

              <div className="login-button">
                <button type='submit'>Sign Up</button>
              </div>
            </div>
          </form>
        )}
      </div>
      <div className="login-img">
        <img src={image} alt="" />
        <div onClick={handleSignUpExit}>
          <CiCircleRemove />
        </div>
      </div>
      {/* Rest of the component */}
    </div>
  );

};

export default RegistrationModal;
 
