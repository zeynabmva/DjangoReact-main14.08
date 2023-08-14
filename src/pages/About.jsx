import { Link } from "react-router-dom"
import { EffectFade } from "swiper";
import React, { useRef, useState ,useEffect} from "react";
// Import Swiper React components
import { Swiper, SwiperSlide } from "swiper/react";
// Import Swiper styles
import "swiper/css";
import "swiper/css/free-mode";
import "swiper/css/pagination";

import { FreeMode, Pagination } from "swiper";

function About() {
    const [data, setData] = useState([])
    useEffect(() => {
        fetch(`http://127.0.0.1:8000/team/list/`)
            .then((a) => a.json())
            .then((a) => setData(a))
    }, [])
    return (
        <>
            <section className="about_first full-container"></section>

            <section className="about_second">
                <div className="container_about">
                    <div className="about_left_second">
                        <img src="/static/image2.png"/>
                    </div>
                    <div className="about_right_second">
                        <h4 className="h4">About us</h4>
                        <h2 className="h2">We do Creative Things for Success</h2>
                        <br></br>
                        <p className="p">Our rich experience helps us in ensuring that the products brought to you are 100% chemical-free. To live a better, healthier, and wholesome life by providing them with 100% certified, authentic organic food.</p>
                        <br></br>
                        <p className="p">Welcome to the world of nature and organic. Here you can discover the bounty of nature. We have grown on the principles of health and care. We aim to give our customers a healthy chemical-free meal for perfect nutrition.</p>
                        <br></br>
                        <div className="about_main_agriculture position">
                            <div className="about_agriculture position">
                                <img className="position" src="/static/Tractor.jpg"></img>
                                Modern Agriculture Equipment
                            </div>
                            <div className="position about_agriculture">
                                <img className="position" src="/static/Chemical Plant.png"></img>
                                No growth hormones are used
                            </div>
                        </div>

                        <Link to="/services">
                            <button className="btn about_second_btn flex">
                                Explore More
                                <div className="arrow">
                                    <i className="fa-solid fa-arrow-right"></i>
                                </div>
                            </button></Link>
                    </div >
                </div >
            </section >

            <section className="about_third">
                <div className="container">
                    <div className="single_flex">

                        <div data-aos="fade-right" className="about_third_left ">
                            <h4 className="h4">Why choose us?</h4>
                            <h2 className="h2">We do not buy from the open market & traders.</h2>
                            <p className="p">Agriculture encompasses crop and livestock production, aquaculture, fisheries and forestry for food and non-food products.</p>
                            <div className="position">
                                <div className="grey_asdiv"><span>100% Natural Product</span></div>
                                <p className="p absolute">We have several collections of organic products and place where you need to choose the product you want.</p>
                            </div>
                            <div className="position"><div className="grey_asdiv second_greydiv"><span>Increases resistance</span></div>
                                <p className="p absolute">Filling, and temptingly healthy, our Biona Organic Granola with Wild Berries is just the thing</p></div>
                        </div>
                        <div  data-aos="fade-left" className="about_third_right">
                            <img src="/static/cucumber.jpg"></img>
                        </div>

                    </div>
                    <div data-aos="fade-up" className="about_third_second_part">
                        <div className="about_info position">
                            <div className="about_info_img position"><img src="/static/Return Purchase.png"></img></div>
                            <h2 className="about_info_h2">Return Policy</h2>
                            <div className="about_pp"><p className="p">If the product having any issues you can return the product.</p></div>

                        </div>
                        <div className="about_info position">
                            <div className="about_info_img position"><img src="/static/Natural Food.png"></img></div>
                            <h2 className="about_info_h2">100% Fresh</h2>
                            <div className="about_pp">
                                <p className="p">Fully organic and fresh products are delivered at door step.</p>
                            </div>
                        </div>
                        <div className="about_info position">
                            <div className="about_info_img position"><img src="/static/Phone Time.png"></img></div>
                            <h2 className="about_info_h2">Support 24/7</h2>
                            <div className="about_pp">
                                <p className="p">Our support team is available for take care the customers.</p>
                            </div>
                        </div>
                        <div className="about_info position">
                            <div className="about_info_img position"><img src="/static/Card Security.png"></img></div>
                            <h2 className="about_info_h2">Secured Payment</h2>
                            <div className="about_pp">
                                <p className="p">Fully secured payment methods are used for buying product.</p>
                            </div>
                        </div>
                    </div>
                </div>
            </section>

            <section className="about_fourth about_swipper">
                <div className="container">
                    <div className="about_center" data-aos="zoom-in">
                        <h4 className="h4">Team</h4>
                        <h2 className="h2">Our Organic Experts</h2>
                        <p className="p">We have grown on the principles of health, ecology, and care. We aim to give our customers a healthy chemical-free meal for perfect nutrition.</p>
                    </div>
                    <div className="about_experts">
                        <Swiper
                            slidesPerView={3}
                            spaceBetween={30}
                            freeMode={true}
                            pagination={{
                            clickable: true,
                            }}
                            modules={[FreeMode, Pagination]}
                            className="mySwiper"
                        >
                            {data.map((a)=>(
                            <SwiperSlide>
                                <div className="about_expert">
                                    <div className="about_expert_img">
                                        <img src={a.image}></img>
                                    </div>
                                    <div className="about_expert_infos">
                                        <h2 className="about_blue">{a.name}</h2>
                                        <div className="about_expert_infoss">
                                            <h4 className="h4">{a.profession}</h4>
                                            <div className="about_info_i">
                                                    {a.facebook && <a href={a.facebook}><img src="/static/facebook.png" alt="Facebook"></img></a>}
                                                    {a.twitter && <a href={a.twitter}><img src="/static/twitter.png" alt="Twitter"></img></a>}
                                                    {a.instagram && <a href={a.instagram}><img src="/static/Insta.png" alt="Instagram"></img></a>}

                                                 
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </SwiperSlide>
                        ))}
                        </Swiper>
                    </div>
                </div>
            </section>
            {/* <a href="https://www.facebook.com/"><img src="/facebook.png"></img></a> */}

            <section className="about_fifth">
                <div className="container">
                    <div className="about_center" data-aos="zoom-in">
                        <h4 className="h4">About us</h4>
                        <h2 className="h2 white">What We Offer for You</h2>
                    </div>
                    <div className="about_products">
                        <div data-aos="fade-right" className="about_product">
                            <div className="about_product_img">
                                <img src="/static/spicy.png"></img>
                            </div>
                            <div className="about_product_name">
                                <h2>Spicy</h2>
                            </div>
                        </div>
                        <div data-aos="fade-right" className="about_product">
                            <div className="about_product_img">
                                <img src="/static/nuts.png"></img>
                            </div>
                            <div className="about_product_name">
                                <h2>Nuts & Feesd</h2>
                            </div>
                        </div>
                        <div data-aos="fade-left" className="about_product">
                            <div className="about_product_img">
                                <img src="/static/fruits.png"></img>
                            </div>
                            <div className="about_product_name">
                                <h2>Fruits</h2>
                            </div>
                        </div>
                        <div data-aos="fade-left" className="about_product">
                            <div className="about_product_img">
                                <img src="/static/vegetable.png"></img>
                            </div>
                            <div className="about_product_name">
                                <h2>Vegetable</h2>
                            </div>
                        </div>
                    </div>
                </div>

            </section>
        </>
    )
}

export default About