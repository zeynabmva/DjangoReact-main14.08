import React from "react";
import { Link } from "react-router-dom";
import { connect } from "react-redux";
function PaymentModal({
  paymentModalShown,
  setPaymentModalShown,

  dispatch,
  products,
  basket,
}) {
  const total = basket.reduce((acc, item) => {
    let product = products.find((a) => a.id === item.id);
    return acc + product?.newprice * item?.count;
  }, 0);
  console.log(total);

  const removeProduct = (id) => {
    dispatch({
      type: "SET_BASKET",
      payload: [...basket.filter((a) => a.id !== id)],
    });
  };
  return (
    <div id="myPayModal" class="pay_modal">
      <div className="pay_modal_inner">
        <div className="pay_modal_header">
          <h4>Payment Process</h4>
          <span
            onClick={() => setPaymentModalShown(!paymentModalShown)}
            className="close"
          >
            &times;
          </span>
        </div>
        <hr />
        <div className="pay_modal_card_products">
          <div className="pay_modal_card_information">
          <div data-aos="fade-up" className="form_row">
              <div className="form_form">
                <label for="card_number" className="form_label">
                  Card Number*
                </label>
                <input
                  type="number"
                  className="form_input"
                  maxlength="10"
                  placeholder="MM / YY"
                  id="card_number"
                />
              </div>
              
            </div>
            <div data-aos="fade-up" className="form_row">
              <div className="form_form">
                <label for="card_date" className="form_label">
                  Expiration Date*
                </label>
                <input
                  type="number"
                  className="form_input"
                  maxlength="10"
                  placeholder="MM / YY"
                  id="card_date"
                />
              </div>
              
            </div>
            <div data-aos="fade-up" className="form_row">
             
            <div className="form_form">
                <label for="card_scode" className="form_label">
                  Security Code*
                </label>
                <input
                  type="number"
                  className="form_input"
                  maxlength="3"
                  placeholder="CVC"
                  id="card_scode"
                />
              </div>
            </div>
          </div>
          <div className="pay_modal_products">
            {basket.length ? (
              basket.map((a) => {
                let p = products.find((t) => t.id === a.id);
                return (
                  <>
                    <div className="pay_modal_product">
                      <div class="pay_modal_product_content">
                        <div className="pay_modal_image_about">
                          <div className="pay_modal_product_image">
                            <img src={p?.images} alt="" />
                          </div>
                          <div className="pay_modal_product_about">
                            <h6 className="pay_modal_product_name">
                              {p?.name}
                            </h6>
                            <h5 className="pay_modal_product_price">
                              ${p?.newprice.toFixed(2)}
                            </h5>
                          </div>
                        </div>

                        <div className="pay_modal_product_count">
                          x {a.count}
                        </div>
                      </div>

                      <div
                        onClick={() => removeProduct(p.id)}
                        className="pay_modal_product_remove"
                      >
                        Remove
                      </div>
                    </div>
                  </>
                );
              })
            ) : (
              <Link to="/shop">
                <button
                  onClick={() => setPaymentModalShown(!paymentModalShown)}
                  className="pay_modal_blue_btn"
                >
                  <p>GO TO SHOPPING</p>
                  <i className="fa-solid fa-circle-arrow-right"></i>
                </button>
              </Link>
            )}
          </div>
        </div>

        <hr />
        <div className="modal_total_payment">
          <div className="modal_total">
            <div className="modal_total_text">Total</div>
            <div className="modal_total_price">${total.toFixed(2)} </div>
          </div>
          <Link to="/delivery">
            <div
              onClick={() => setPaymentModalShown(!paymentModalShown)}
              className="modal_payment"
            >
              <div className=" blue_btn">
                <p>Complete</p>
                <i className="fa-solid fa-circle-arrow-right"></i>
              </div>
            </div>
          </Link>
        </div>
      </div>
    </div>
  );
}
const t = (a) => a;
export default connect(t)(PaymentModal);
