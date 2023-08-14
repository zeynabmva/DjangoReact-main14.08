import React from 'react';
import { useEffect, useState } from "react";
// import loginIcons from "../images/login.jpg";
import { CiCircleRemove } from "react-icons/ci";
import axios from 'axios';

const LoginModal = ({
  handleLogin,
  handleSignUp,
 
}) => {
  const [currentUser, setCurrentUser] = useState()
  const [registrationToggle, setRegistrationToggle] = useState(false)
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  
  const handleSubmit = async (e) => {
    e.preventDefault();
     
    const LoginData = {
      email: email,
      password: password
    };
    fetch('http://127.0.0.1:8000/api/accounts/login/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(LoginData)
    })
      .then(response => response.json())
      .catch(error => {
        console.log(error.JSON)
      })
  }
  return (
    <div className="login-wrapper">
      <div className="login-input">
        <form method='post' onSubmit={handleSubmit}>
        <div className="login-input-head">
            <div className="org">Organick</div>
            <div className="login-input-head-title">
              <p>Welcome Back</p>
              <p className="p login_p">Login in with your email address and password</p>
            </div>
        </div>

        <div className="login-input-title">

          <div>
            <label htmlFor="email">Email Address</label>
            <input
              id='email'
              onChange={(e) => setEmail(e.target.value)}
              name="email"
              value={email}
              type="email"
              required
              placeholder="Enter your email..." />
          </div>
          <div>
            <label htmlFor="password">Password</label>
            <input
              id='password'
              onChange={(e) => setPassword(e.target.value)}
              name="password"
              value={password}
              type="text"
              placeholder="Password"
              required
            />
          </div>

          <div>
            <div className="login-remember">
              <input type="checkbox" name="Remember me" id="" />
              <label htmlFor="">Remember me</label>
            </div>
          </div>

          <div className="login-button">
            <button type="submit">Sign In</button>
          </div>
          
        </div>

        </form>
        <div className="sign-up" onClick={handleSignUp}>
          <p>Don't have an account?</p>
          <p className="blue-sign">Sign Up</p>
        </div>
        {/* <div className="sing-up" onClick={handleSignUpVendor}>
          <p>Vendor create account</p>
          <p>Sign Up</p>
        </div> */}
      </div>
        <div className="login-img">
          <img src={"/static/login.jpg"} alt="" />
          <div onClick={handleLogin}>
            <CiCircleRemove />
          </div>

       
      </div>
    </div>

  );
};

export default LoginModal;
