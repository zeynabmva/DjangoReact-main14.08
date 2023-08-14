import React from "react";
import { Link } from "react-router-dom";
import { connect } from "react-redux";

function FavoriteModal({
  favoriteModalShown,
  setFavoriteModalShown,
  dispatch,
  products,
  favorite,
}) {
  const removeProduct = (id) => {
    dispatch({
      type: "SET_FAVORITE",
      payload: [...favorite.filter((a) => a.id !== id)],
    });
  };

  return (
    <div id="myModal" className="modal">
      <div className="modal_inner">
        <div className="modal_header">
          <h4>Your Favorities</h4>
          <span
            onClick={() => setFavoriteModalShown(!favoriteModalShown)}
            className="close"
          >
            &times;
          </span>
        </div>
        <hr />

        {favorite.length ? (
          favorite.map((a) => {
            let p = products.find((t) => t.id === a.id);
            return (
              <>
                <div className="modal_product">
                  <div className="modal_product_content">
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

                    <div>
                      <Link to={`/shop-single/${p.id}`}>
                        <h5
                          onClick={() =>
                            setFavoriteModalShown(!favoriteModalShown)
                          }
                          className="add_cart_text_in_favorite"
                        >
                          BUY NOW
                        </h5>
                      </Link>
                    </div>
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
              onClick={() => setFavoriteModalShown(!FavoriteModalShown)}
              className="modal_blue_btn"
            >
              <p>GO TO SHOPPING</p>
              <i className="fa-solid fa-circle-arrow-right"></i>
            </button>
          </Link>
        )}

        <hr />
      </div>
    </div>
  );
}
const t = (a) => a;
export default connect(t)(FavoriteModal);
