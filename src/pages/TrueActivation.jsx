import { useState, useEffect } from "react"
import React from "react"
import LoginModal from "../components/LoginModal";
import RegistrationModal from "../components/RegistrationModal";

function TrueActivation() {
    const [isLogin, setIsLogin] = useState(false);
    const [regst, setRegst] = useState(false);
    const handleLogin = () => {
        setIsLogin(true);
    };
    const handleSignUp = () => {
        setIsLogin(false);
        setRegst(true);
    };

    const handleSignUpExit = () => {
        setRegst(false);
    
    };
    return (
        <>
            <section className="activate_back">
                <div className="active_center">
                    <h1 className="h2">Let's Shopping</h1>
                    <h3 className="success">Success</h3>
                    <img src="/static/7success.gif" ></img>
                    <button className="blue_btn" onClick={handleLogin}>
                        <p className="p">Login now</p>
                    </button>
                </div>
            </section>
            {isLogin && (
                <LoginModal
                    handleLogin={handleLogin}
                    handleSignUp={handleSignUp}
                />
            )}
            {regst && (
                <RegistrationModal
                    handleSignUpExit={handleSignUpExit}
                />
            )}
        </>
    )
}

export default TrueActivation