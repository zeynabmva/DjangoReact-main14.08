import React from 'react'

function Service_single() {
  return (
    <>
      <section className="service_single_banner full-container"></section>

      <section className="service_single_main container">
        <div className="service_single_image">
          <img src="/static/service_single_photo.jpg" />
        </div>
        <div className="serivice_single_content service_container">
          <div className="service_single_text">
            <h2>Organic Store Services</h2>
            <p>
            Our organic store services provide a wide range of organic products, including fresh produce, dairy, meat, and pantry staples, all sourced from local and trusted organic farmers.
We take pride in our knowledgeable and friendly staff who are always ready to assist you in finding the best organic products to fit your needs and preferences.<br /><br />
Our organic store services also offer convenient online ordering and delivery options, making it easier for you to access fresh and healthy organic foods from the comfort of your own home.
            </p>
          </div>
          <div className="service_single_row">
            <div className="service_single_row_image">
              <img src="/static/service_single_row1.jpg" />
            </div>
            <div className="service_single_row_text">
              <h4>Why Organic</h4>
              <p>
              Many people choose organic food because it is grown without the use of synthetic pesticides and fertilizers, which can be harmful to human health and the environment.
              </p>
            </div>
          </div>
          <div className="service_single_row">
            <div className="service_single_row_text">
              <h4>Speciality Produce</h4>
              <p>
              Our speciality produce is sourced from local farms and growers who use sustainable and organic practices to ensure the highest quality products.
              </p>
            </div>
            <div className="service_single_row_image">
              <img src="/static/service_single_row2.jpg" />
            </div>
          </div>
          <div className="service_single_text">
            <h2>We farm your land</h2>
            <p>
            Our "We Farm Your Land" program provides you with the opportunity to have your own personal farm without having to do any of the work.Our team of skilled farmers will come to your land and use sustainable and organic farming practices to cultivate a variety of fresh produce for you.
            </p>
            <div className="service_single_quality">
              <div className="quality_item">
                <div className="quality_number"><h3>01</h3></div>
                <h4>Best quality support</h4>
              </div>
              <div className="quality_item">
                <div className="quality_number"><h3>02</h3></div>
                <h4>Money back guarantee</h4>
              </div>
            </div>
          </div>
        </div>
      </section>
    </>
  )
}

export default Service_single