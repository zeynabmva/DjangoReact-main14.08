import React from 'react';

function Footer() {
  return (
    <>
          <section className="footer_first">
            <div className="container position">
                  <img src="/static/Backgroundd.png"></img>
                  <div className ="footer_first_info footer_first_info_display">
                      <div>
                          <h1 className="footer_subscribe">Subscribe to our Newsletter</h1>
                      </div>
                      <div className="footer_first_subscribe">
                          <input type="text" placeholder="Your Email Address"></input>
                          <button className="btn">Subscribe</button>
                      </div>
                  </div>
            </div> 
          </section>

          <section className="footer_second full-container">
              <div className="mains_footer_second">
                  <div className="main_footer_second footer_contact">
                      <h2>Contact Us</h2>
                      <ul className="footer_contact_ul">
                          <li>
                              <h3>Email</h3>
                              <a href="mailto:needhelp@Organia.com">needhelp@Organia.com</a>
                          </li>
                          <li>
                              <h3>Phone</h3>
                              <a href="tel:666 888 888">666 888 888</a>
                          </li>
                          <li>
                              <h3>Address</h3>
                              <a href="https://yandex.ru/maps/?ll=-120.373962%2C38.548978&pt=-120.3774722%2C38.54440556&source=entity_search&z=13.41">88 road,borkly street,USA</a>
                          </li>
                      </ul>
                  </div>
                  <div className="main_footer_second footer_organic">
                      <div className='main_organic_footer'>
                          <img src="/static/organick.png"></img>
                      </div>
                      <p className="p">We are a popular and farming company aspiring to be a leader in the Organic food industry.</p>
                      <div className="footer_organic_img">
                          <div className="footer_img_circle">
                            <a href="https://www.instagram.com/"><img  src="/static/Insta.png"></img></a></div>
                          <div className="footer_img_circle">
                            <a href="https://www.facebook.com/"><img src="/static/facebook.png"></img></a></div>
                          <div className="footer_img_circle">
                              <a href="https://twitter.com/"><img src="/static/twitter.png"></img></a></div>
                          <div className="footer_img_circle">
                              <a href="https://www.pinterest.com/"><img src="/static/Pintrest.png"/></a>
                            </div>
                      </div>
                  </div>
                  <div className="main_footer_second main_footer_utility">
                      <h2>Utility Pages</h2>
                      <ul>
                          <li>Style Guide</li>
                          <li>404 Not Found</li>
                          <li>Password Protected</li>
                          <li>Licences</li>
                          <li>Changelog</li>
                      </ul>
                  </div>
              </div>

          </section>
          <section className="footer_third">
              <h4>Copyright © Organick | Designed by VictorFlow Templates - Powered by Webflow</h4>
          </section>
    </>
  )
}

export default Footer