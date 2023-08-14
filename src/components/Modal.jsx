import React from "react";
import { Link } from "react-router-dom";
import { connect } from "react-redux";
function Modal({
  modalShown,
  setModalShown,
  number,
  dispatch,
  products,
  basket,
}) {
  console.log(number);
  console.log(basket);
  // let total = 0
  // basket.map(a => {
  //   total += +a.count * +products.find(b => b.id === a.id).price
  // })
  // console.log("total : "+total)
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
    <div id="myModal" class="modal">
      <div className="modal_inner">
        <div className="modal_header">
          <h4>Your Cart</h4>
          <span onClick={() => setModalShown(!modalShown)} className="close">
            &times;
          </span>
        </div>
        <hr />

        {basket.length ? (
          basket.map((a) => {
            let p = products.find((t) => t.id === a.id);
            return (
              <>
                <div className="modal_product">
                  <div class="modal_product_content">
                    <div className="modal_image_about">
                      <div className="modal_product_image">
                        <img src={p?.image} alt="" />
                      </div>
                      <div className="modal_product_about">
                        <h6 className="modal_product_name">{p?.name}</h6>
                        <h5 className="modal_product_price">
                          ${p?.newprice.toFixed(2)}
                        </h5>
                      </div>
                    </div>

                    <div className="modal_product_count">x {a.count}</div>
                  </div>

                  <div
                    onClick={() => removeProduct(p.id)}
                    className="modal_product_remove"
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
              onClick={() => setModalShown(!modalShown)}
              className="modal_blue_btn"
            >
              <p>GO TO SHOPPING</p>
              <i className="fa-solid fa-circle-arrow-right"></i>
            </button>
          </Link>
        )}

        <hr />
        <div className="modal_total_payment">
          <div className="modal_total">
            <div className="modal_total_text">Total</div>
            <div className="modal_total_price">${total.toFixed(2)} </div>
          </div>
          {basket.length?(
          <Link to="/delivery">
          <div onClick={() => setModalShown(!modalShown)} className="modal_payment">
            <div className=" blue_btn">
              <p>Make your Payment</p>
              <i className="fa-solid fa-circle-arrow-right"></i>
            </div>
          </div>
          </Link>
          ):(<></>)}
         
          
        </div>
      </div>
    </div>
  );
}
const t = (a) => a;
export default connect(t)(Modal);
