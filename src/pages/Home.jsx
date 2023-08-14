import { Link } from "react-router-dom";
import React, { useEffect, useState } from "react";
import Product from "../components/Product";
import { Swiper, SwiperSlide } from "swiper/react";
import "swiper/css/autoplay";
import { Autoplay, EffectFade } from "swiper";
// Import Swiper styles
import "swiper/css";
import "swiper/css/navigation";

// import required modules
import { Navigation } from "swiper";

// import data from "../data.json";
function Home() {
  const [products, setProducts] = useState([]);
  useEffect(() => {
    fetch("http://127.0.0.1:8000/shop-product/list/")
      .then((a) => a.json())
      .then((a) => setProducts(a));
  }, []);
  return (
    <>
      <section className="home_hero full-container">
        <div className="container">
          <div className="home_hero_content">
            <div className="home_title">
              <h5>100% Natural Food</h5>
              <h3>Choose the best healthier way of life.</h3>
            </div>
            <Link to="/about">
              <button className="yellow_btn">
                <p>Explore More</p>
                <i className="fa-solid fa-circle-arrow-right"></i>
              </button>
            </Link>
          </div>
        </div>
      </section>

      <section   className="home_natural_offer container">
        <div data-aos="fade-right" className="home_natural">
          <img src="static/home_natural.png" />
          <div className="title">
            <h5>Natural!!</h5>
            <h4>
              Get Garden <br />
              Fresh Fruits
            </h4>
          </div>
        </div>
        <div data-aos="fade-left" className="home_offer">
          <img src="static/home_offer.png" />
          <div className="title">
            <h5>Offer!!</h5>
            <h4>
              Get 10% off
              <br />
              on Vegetables
            </h4>
          </div>
        </div>
      </section>

      <section  className="home_about full-container">
        <div className="home_about_inner container">
          <div data-aos="fade-up" className="home_about_image">
            <img src="static/home-about-img.png" />
          </div>
          <div className="home_about_content">
            <div  data-aos="fade-up" className="home_title">
              <h5>About Us</h5>
              <h3>We Believe in Working Accredited Farmers</h3>
              <p>
                Many people believe that organic foods are healthier because
                they are grown without the use of harmful pesticides and
                fertilizers. Organic farming practices prioritize sustainability
                and biodiversity, making organic foods a more environmentally
                responsible choice
              </p>
            </div>
            <div className="home_about_points">
              <div data-aos="fade-up" className="point1">
                <div className="point_img">
                  <img src="/static/home_about_icon1.png" />
                </div>

                <div className="point_text">
                  <h6>Organic Foods Only</h6>
                  <p>
                    Choosing organic products is not only good for your health,
                    but also for the environment.
                  </p>
                </div>
              </div>
              <div data-aos="fade-up" className="point2">
                <div className="point_img">
                  <img src="static/home_about_icon2.png" />
                </div>
                <div className="point_text">
                  <h6>Quality Standards</h6>
                  <p>
                    Trust us to provide you with the best selection of organic
                    products on the market.
                  </p>
                </div>
              </div>
            </div>
            <Link to="/shop">
              <button data-aos="fade-up" className="blue_btn">
                <p>Shop Now</p>
                <i className="fa-solid fa-circle-arrow-right"></i>
              </button>
            </Link>
          </div>
        </div>
      </section>

      <section data-aos="fade-up" className="home_our_products ">
        <div className="container">
        <div className="home_title">
          <h5>Categories</h5>
          <h3>Our Products</h3>
        </div>
        <div className="home_our_products_content">
          <div className="home_products">
            {products.slice(0, 8).map((a) => (
              <Product data={a} key={a.id} />
            ))}
          </div>
          <Link to="/shop">
            <button className="blue_btn">
              <p>Load More</p>
              <i className="fa-solid fa-circle-arrow-right"></i>
            </button>
          </Link>
        </div>
        </div>
      </section>

      <section className="home_customer_big_background full-container">
        <div className="home_customer_section container">
          <div data-aos="fade-up" className="home_title">
            <h5>Testimonial</h5>
            <h3>What Our Customer Saying?</h3>
          </div>

          <div data-aos="fade-up" className="home_customer_main">
            <Swiper
              autoplay={{ delay: 4500 }}
              modules={[Autoplay, Navigation]}
              navigation={true}
              className="mySwiper"
            >
              <SwiperSlide>
                <div className="home_customer_inner">
                  <div className="home_customer_image">
                    <img src="static/client-image-2.jpg" />
                  </div>

                  <div className="home_customer_rating">
                    <img src="static/stars.svg" />
                  </div>
                  <div className="home_customer_content">
                    <p>
                      The quality of organic produce is extremely high, the
                      service is second to none and the taste of the food takes
                      me back to my childhood when we were growing our own.
                    </p>
                    <h4>Sara Taylor</h4>
                    <h6>Consumer</h6>
                  </div>
                </div>
              </SwiperSlide>
              <SwiperSlide>
                <div className="home_customer_inner">
                  <div className="home_customer_image">
                    <img src="static/client-image-1.jpg" />
                  </div>

                  <div className="home_customer_rating">
                    <img src="static/stars.svg" />
                  </div>
                  <div className="home_customer_content">
                    <p>
                      I have been using the Organick Grocer for over a year now
                      and I find the staff friendly and helpful with a good
                      knowledge of the products they sell.
                    </p>
                    <h4>Chris Jordan</h4>
                    <h6>Store Owner</h6>
                  </div>
                </div>
              </SwiperSlide>
            </Swiper>
          </div>

          <div className="divider_line"></div>

          <div data-aos="fade-up" className="home_statistics">
            <div className="circle">
              <div className="circle_white_border"></div>
              <div className="home_static_content">
                <h2>100%</h2>
                <p>Organic</p>
              </div>
            </div>

            <div className="circle">
              <div className="circle_white_border"></div>
              <div className="home_static_content">
                <h2>285</h2>
                <p>Active Product</p>
              </div>
            </div>

            <div className="circle">
              <div className="circle_white_border"></div>
              <div className="home_static_content">
                <h2>350+</h2>
                <p>Organic Orchads</p>
              </div>
            </div>

            <div className="circle">
              <div className="circle_white_border"></div>
              <div className="home_static_content">
                <h2>25+</h2>
                <p>Years of Farming</p>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section className="home_offer_blue full-container">
        <div  className="home_offer_organic container">
          <div data-aos="fade-up" className="offer_title_button">
            <div className="home_title">
              <h5>Offer</h5>
              <h3>We Offer Organic For You</h3>
            </div>
            <Link to="/shop">
              <button className="yellow_btn">
                <p>View All Product</p>
                <i className="fa-solid fa-circle-arrow-right"></i>
              </button>
            </Link>
          </div>

          <div  data-aos="fade-up" className="home_offer_products">
            {products.slice(3, 7).map((a) => (
              <Product data={a} key={a.id} />
            ))}
          </div>
        </div>
      </section>

      <section className="home_eco full-container">
        <div className="home_eco_image">
          <img src="static/eco-image.jpg" />
        </div>

        <div className="eco_white_content">
          <div data-aos="fade-up" className="home_title">
            <h5>Eco Friendly</h5>
            <h3>Econis is a Friendly Organic Store</h3>
          </div>

          <div  data-aos="fade-up" className="eco_list_item">
            <h3>Start with Our Company First</h3>
            <p>
            Our company is committed to providing customers with the freshest, highest quality organic foods available.
            </p>
          </div>

          <div data-aos="fade-up" className="eco_list_item">
            <h3>Learn How to Grow Yourself</h3>
            <p>
            If you're interested in learning about organic foods, we offer a variety of educational resources and classes to help you get started.
            </p>
          </div>
          <div  data-aos="fade-up" className="eco_list_item">
            <h3>Farming Strategies of Today</h3>
            <p>
            We believe that everyone deserves access to healthy, nutritious organic foods, and we work hard to make our products affordable and accessible to all
            </p>
          </div>
        </div>
      </section>

      <section className="bg_gray full-container">
        <div  data-aos="fade-up" className="home_fon">
          <div className="fon">
            <img src="static/juice.jpg" />
            <Link to="/service-single">
              <a href="#" className="fon_btn">Organic Juice</a>
            </Link>
          </div>

          <div className="fon">
            <img src="static/yarpaq-food.jpg" />
            <Link to="/service-single">
              <a href="#" className="fon_btn">
               Organic Food
              </a>
            </Link>
          </div>

          <div className="fon">
            <img src="static/cookies.jpg" />
            <Link to="/service-single">
              <a href="#" className="fon_btn">
                Nuts Cookies
              </a>
            </Link>
          </div>
        </div>
      </section>

      <section className="home_blog container">
        <div className="home_blog_title_main">
          <div className="home_blog_title">
            <div data-aos="fade-up" className="blog_title_button">
              <div className="home_title">
                <h5>News</h5>
                <h3>Discover The Recent Content About Organic Products</h3>
              </div>
              <Link to="/blog">
                <button className="yellow_btn">
                  <p>More News</p>
                  <i className="fa-solid fa-circle-arrow-right"></i>
                </button>
              </Link>
            </div>
          </div>
          <div className="home_blog_main">
            <div data-aos="fade-up" className="blog_item">
              <div className="blog_item_image">
                <a href="#">
                  <img src="static/home_blog_image1.png" />
                </a>
                <div className="blog_item_date">
                  <h6>14 Feb</h6>
                </div>
              </div>
              <div className="blog_item_content">
                <div className="blog_author">
                  <img src="static/blog_author.png" />
                  <a href="#">Kristina Castle</a>
                </div>
                <div className="blog_title_area">
                  <a className="blog_title_link" href="#">
                    The Benefits of Vitamin D & How to Get It
                  </a>
                  <p>
                  Eating organic foods can help reduce exposure to harmful chemicals and toxins that are commonly found in conventionally grown produce and processed foods.
                  </p>
                </div>
                <Link to="/blog/blog_single/1">
                  <button className="yellow_btn">
                    <p>Read More</p>
                    <i className="fa-solid fa-circle-arrow-right"></i>
                  </button>
                </Link>
              </div>
            </div>

            <div data-aos="fade-up" className="blog_item">
              <div className="blog_item_image">
                <a href="#">
                  <img src="static/home_blog_image2.png" />
                </a>
                <div className="blog_item_date">
                  <h6>14 Feb</h6>
                </div>
              </div>
              <div className="blog_item_content">
                <div className="blog_author">
                  <img src="static/blog_author.png" />
                  <a href="#">By Rachi Card</a>
                </div>
                <div className="blog_title_area">
                  <a className="blog_title_link" href="#">
                    Our Favourite Summertime Tommeto</a>
                  <p>
                  Organic tomatoes, in particular, are often sweeter and more flavorful than their conventionally grown counterparts, since they're allowed to ripen on the vine and are free from synthetic pesticides and fertilizers.
                  </p>
                </div>
                <Link to="/blog/blog_single/2">
                  <button className="yellow_btn">
                    <p>Read More</p>
                    <i className="fa-solid fa-circle-arrow-right"></i>
                  </button>
                </Link>
              </div>
            </div>
          </div>
        </div>
      </section>
    </>
  );
}

export default Home;
