import React, { useReducer, useEffect, useState } from "react";


function Contact() {
    const [formData, setFormData] = useState({
        name: '',
        email: '',
        message: ''
      });
    
      const handleChange = (e) => {
        setFormData({
          ...formData,
          [e.target.name]: e.target.value,
        });
      };
      
      const handleSubmit = async (e) => {
        e.preventDefault();
        try {
          const response = await fetch('contact/', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify(formData),
          });
    
          const data = await response.json();
          if (response.ok) {
            // E-posta gönderimi başarılıysa
            alert('Teşekkürler! İletişim bilgileriniz kaydedildi.');
          } else {
            // E-posta gönderimi başarısızsa
            alert('Formu göndermek mümkün olmadı: ' + data.error);
          }
        } catch (error) {
          // E-posta gönderme işlemi sırasında bir hata oluştu
          alert('Formu göndermek mümkün olmadı: ' + error.message);
        }
      };

  return (
    <>
      <section className="contact_banner full-container"></section>
      <section className="find_out container">
        <div data-aos="fade-up" className="find_out_image">
          <img src="/static/find_out_img.jpg" />
        </div>
        <div className="find_out_content">
          <div data-aos="fade-up" className="find_out_title">
            <h3>We'd love to talk about how we can work together.</h3>
            <p>
              We value partnerships and are excited about the prospect of
              working with you to promote organic products and sustainable
              agriculture.Let's join forces and make a difference in the world
              of organic farming. We're eager to explore how we can work
              together.
            </p>
          </div>
          <div className="find_out_info">
            <div data-aos="fade-up" className="info_item">
              <div className="info_item_icon">
                <img src="/static/message.png" />
              </div>
              <div className="info_item_text">
                <h4>Massege</h4>
                <a href="#">support@organic.com</a>
              </div>
            </div>

            <div data-aos="fade-up" className="info_item">
              <div className="info_item_icon">
                <img src="/static/phone.png" />
              </div>
              <div className="info_item_text">
                <h4>Contact Us</h4>
                <a href="#">+01 123 456 789</a>
              </div>
            </div>
          </div>
          <div data-aos="fade-up" className="contact_social">
            <a href="https://www.facebook.com/">
              <img src="/static/facebook.png" />
            </a>
            <a href="https://twitter.com/">
              <img src="/static/Twiter.png" />
            </a>
            <a href="https://www.instagram.com/">
              <img src="/static/Insta.png" />
            </a>
            <a href="https://www.pinterest.com/">
              <img src="/static/Pintrest.png" />
            </a>
          </div>
        </div>
      </section>
      <section className="location_section container">
        <div data-aos="fade-up" className="location_content">
          <div data-aos="fade-up" className="location_title">
            <h5>Location</h5>
            <h3>Our Farms</h3>
            <p>
              With farms located in various regions, we are able to offer a wide
              variety of organic produce all year round.
            </p>
          </div>
          <div className="location_about">
            <div data-aos="fade-up" className="location_adress">
              <div className="location_icon">
                <img src="/static/location_icon.png" />
              </div>
              <div className="location_text">
                <h6 className="adress_title">New York, USA:</h6>
                <p>299 Park Avenue New York, New York 10171</p>
              </div>
            </div>

            <div data-aos="fade-up" className="location_adress">
              <div className="location_icon">
                <img src="/static/location_icon.png" />
              </div>
              <div className="location_text">
                <h6 className="adress_title">London, UK:</h6>
                <p>30 Stamford Street, London SE1 9LQ</p>
              </div>
            </div>
          </div>
        </div>
      </section>
      <section className="contact_form container">
        <form method="post" onSubmit={handleSubmit}>
          <div data-aos="fade-up" className="form_row">
            <div className="form_form">
              <label htmlFor="full_name" className="form_label">
                Full Name*
              </label>
              <input
                type="text"
                className="form_input"
                maxLength="256"
                placeholder="Enter Your Name"
                id="full_name"
                required
                value={formData.name}
                onChange={handleChange}
                name="name"
              />
            </div>
            <div className="form_form">
              <label htmlFor="full_email" className="form_label">
                Email Address*
              </label>
              <input
                type="email"
                className="form_input"
                
                maxLength="256"
                placeholder="Enter Your Email"
                id="full_email"
                required
                value={formData.email}
                onChange={handleChange}
                name="email"
              />
            </div>
          </div>
          {/* <div data-aos="fade-up" className="form_row">
                        <div className="form_form">
                            <label for="company" className="form_label">Company*</label
                            ><input
                                type="email"
                                className="form_input"
                                maxlength="256"
                                placeholder="Enter Company Name"
                                id="company"
                            />
                        </div>
                        <div className="form_form">
                            <label for="subject" className="form_label">Subject*</label
                            ><input
                                type="text"
                                className="form_input"
                                maxlength="256"
                                placeholder="How We Can Help"
                                id="subject"
                            />
                        </div>
                    </div> */}
          <div data-aos="fade-up" className="form_message">
            <label htmlFor="message" className="form_label">
              Message
            </label>
            <textarea
              placeholder="Hello There, I would like to..."
              maxLength="5000"
              id="message"
              className="input_textarea"
              name="message"
              value={formData.message}
              onChange={handleChange}
            ></textarea>
          </div>
          <button data-aos="fade-up" className="blue_btn">
            <p>Send Message</p>
            <i className="fa-solid fa-circle-arrow-right"></i>
          </button>
        </form>
      </section>
    </>
  );
}

export default Contact;
