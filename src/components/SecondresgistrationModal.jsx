 
import { CiCircleRemove } from "react-icons/ci";
import React from "react";

const RegistrationModal = ({
  handleSignUpExit,
  dataFormVendor,
  setDataFormVendor,
  dataFormInputVendor,
  setDataFormInputVendor,
}) => {
  const handleSignUpVendor = (e) => {
    const { name, value } = e.target;
    setDataFormInputVendor((prev) => {
      return {
        ...prev,
        [name]: value,
      };
    });
  };
  const handleSignUpVendorButton = () => {
    setDataFormVendor([...dataFormVendor, dataFormInputVendor]);
  };

  return (
    <div className="login-wrapper">
      <div className="login-input">
        <div className="login-input-head">
          <div className="org">Vendor Registration</div>
          <div className="login-input-head-title">
            <p>Welcome Back</p>
            <p>Login in with your email address and password</p>
          </div>
        </div>
        <div className="login-input-title">
          <div>
            <label htmlFor="">Name</label>
            <input
              onChange={handleSignUpVendor}
              name="name"
              value={dataFormInputVendor.name}
              type="text"
              placeholder="Enter your name..."
            />
          </div>
          <div>
            <label htmlFor="">Username</label>
            <input
              onChange={handleSignUpVendor}
              name="username"
              value={dataFormInputVendor.username}
              type="text"
              placeholder="Username"
            />
          </div>
          <div>
            <label htmlFor="">Create your password</label>
            <input
              onChange={handleSignUpVendor}
              name="password"
              value={dataFormInputVendor.password}
              type="password"
              placeholder="Create your password..."
            />
          </div>
          <div className="registr_email">
            <label htmlFor="">Enter your email</label>
            <input
              onChange={handleSignUpVendor}
              name="mail"
              value={dataFormInputVendor.mail}
              type="email"
              placeholder="Enter your email..."
            />
          </div>
          <div className="login-remember">
            <input type="checkbox" name="Remember me" id="" />
            <label htmlFor="">Remember me</label>
          </div>
        </div>
        <div className="login-button">
          <button onClick={handleSignUpVendorButton}>Sign Up</button>
        </div>
      </div>
      <div className="login-img">
        <img src="/static/regis.jpg" alt="" />
        <div onClick={handleSignUpExit}>
          <CiCircleRemove />
        </div>
      </div>
    </div>
  );
};

export default RegistrationModal;
