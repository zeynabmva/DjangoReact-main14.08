import React from 'react'
import { Link } from "react-router-dom";
import { useState } from "react";
import Video from '../components/Video';
function Services() {
  const [videoShown, setVideoShown] = useState(false);
  return (
    <>
      <section className="services_banner full-container"></section>

      <section className="service_main container">
        <div data-aos="fade-up" className="service_title">
          <h5>What we Grow</h5>
          <h3>Better Agriculture for Better Future</h3>
        </div>

        <div className="service_inner">
          <div className="service_product_about">
            <ul className="service_content1">
              <li data-aos="fade-up">
                <img src="/static/icons/service_icon1.svg" />
                <h2>Dairy Products</h2>
                <p>
                Organic dairy products,  come from cows that are raised without the use of antibiotics and synthetic growth hormones, and genetically modified organisms (GMOs).
                </p>
              </li >
              <li data-aos="fade-up">
                <img src="/static/icons/service_icon2.svg" />
                <h2>Store Services</h2>
                <p>
                Our store offers a wide variety of organic products, including fresh produce, dairy products, meats, and pantry items, all of which are sourced from local, organic farmers and producers.
                </p>
              </li>
              <li data-aos="fade-up" >
                <img src="/static/icons/service_icon3.svg" />
                <h2>Delivery Services</h2>
                <p>
                Our delivery service provides a convenient way for you to receive your favorite organic products without leaving the comfort of your home.
                </p>
              </li>
            </ul>
            <div className="service_image">
              <img src="/static/service_product.png" />
            </div>
            <ul className="service_content2">
              <li data-aos="fade-up">
                <img src="/static/icons/service_icon4.svg" />
                <h2>Agricultural Services</h2>
                <p>
                Our team of expert agricultural specialists provides personalized support to organic farmers, offering guidance and advice tailored to their specific needs.
                </p>
              </li>
              <li data-aos="fade-up">
                <img src="/static/icons/service_icon5.svg" />
                <h2>Organic Products</h2>
                <p>
                Organic products are grown and processed without the use of synthetic pesticides or other harmful chemicals, making them a healthier choice for both people and the environment.
                </p>
              </li>
              <li data-aos="fade-up" >
                <img src="/static/icons/service_icon6.svg" />
                <h2>Fresh Vegetables</h2>
                <p>
                Fresh vegetables are a key component of a healthy diet, providing essential vitamins, minerals, and fiber to support overall health and well-being.
                </p>
              </li>
            </ul>
          </div>
          <Link to="/service-single">
               <button className="blue_btn">
            <p>Explore More</p>
            <i className="fa-solid fa-circle-arrow-right"></i>
          </button>
            </Link>
         
        </div>
      </section>

      <section className="service_video_bg full-container">
        <div className="service_video_content container">
          <div data-aos="fade-up" className="service_title">
            <h5>Organic Only</h5>
            <h3>Everyday Fresh & Clean</h3>
            <p>Organic foods are grown without the use of synthetic pesticides and fertilizers, making them a healthier and more sustainable option for both the environment and our bodies.</p>
          </div>
          <div data-aos="fade-up" className="video_play_btn">
            <a onClick={() => setVideoShown(!videoShown)} className="video_play_circle" >
              <div className="play_img"> <img src="/static/play_btn.svg" /> </div>

            </a>
          </div>
        </div>
        {videoShown && <Video videoShown={videoShown} setVideoShown={setVideoShown} />}
      </section>
    </>
  )
}

export default Services