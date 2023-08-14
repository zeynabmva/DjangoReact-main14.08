import React from 'react'
import PaymentModal from "../components/PaymentModal";
import { useState, useEffect } from "react";
import { NavLink, Link, useLocation } from "react-router-dom";
import { connect } from "react-redux";

function Delivery({basket}) {
  const [paymentModalShown, setPaymentModalShown] = useState(false);
  const [data, setData] = useState([]);
  const [filter, setFilter] = useState("")
  return (
    <section className="contact_form delivery_form container">
      <div className="delivery_title">
        <h5>Delivery</h5>
        <h3>Delivery Information</h3>

      </div>


                <div className='form'>
                    <div data-aos="fade-up" className="form_row">
                        <div  className="form_form">
                            <label for="full_name" className="form_label">Full Name*</label
                            ><input
                                type="text"
                                className="form_input"
                                maxlength="256"
                                placeholder="Enter Your Name"
                                id="full_name"
                            />
                        </div>
                        <div className="form_form">
                            <label for="full_email" className="form_label">Email Address*</label
                            ><input
                                type="email"
                                className="form_input"
                                maxlength="256"
                                placeholder="Enter Your Email"
                                id="full_email"
                            />
                        </div>
                    </div>
                    <div data-aos="fade-up" className="form_row">
                        <div className="form_form">
                            <label for="company" className="form_label">Address*</label
                            ><input
                                type="email"
                                className="form_input"
                                maxlength="256"
                                placeholder="Enter Company Name"
                                id="company"
                            />
                        </div>
                        <div className="form_form">
                            <label for="subject" className="form_label">City*</label
                            ><input
                                type="text"
                                className="form_input"
                                maxlength="256"
                                placeholder="How We Can Help"
                                id="subject"
                            />
                        </div>
                    </div>
                    <div data-aos="fade-up" className="form_row">
                        <div className="form_form">
                            <label for="company" className="form_label">Zip Code*</label
                            ><input
                                type="email"
                                className="form_input"
                                maxlength="256"
                                placeholder="Enter Company Name"
                                id="company"
                            />
                        </div>
                        <div className="form_form">
                            <label for="subject" className="form_label">Phone*</label
                            ><input
                                type="text"
                                className="form_input"
                                maxlength="256"
                                placeholder="How We Can Help"
                                id="subject"
                            />
                        </div>
                    </div>
                    
                        
                    
                    <div data-aos="fade-up" className="form_message">
                        <label for="message" className="form_label">Message</label
                        ><textarea
                            placeholder="Hello There, I would like to..."
                            maxlength="5000"
                            id="message"
                            className="input_textarea"
                        ></textarea>
                    </div>
                    <button onClick={() => setPaymentModalShown(!paymentModalShown)}  class="blue_btn">
                        <p>Continue to Payment</p>
                        <i class="fa-solid fa-circle-arrow-right"></i>
                    </button>
                </div>
                {paymentModalShown && <PaymentModal paymentModalShown={paymentModalShown} setPaymentModalShown={setPaymentModalShown} />}
            </section>
  );
}

export default Delivery;