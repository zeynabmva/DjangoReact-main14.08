import React from "react";
import { useParams } from "react-router-dom";
import { useEffect, useState } from "react";
import Product from "../components/Product";
import { connect } from "react-redux";
function Shop_single({ basket, dispatch , favorite }) {
  const [products, setProducts] = useState([]);
  const [selectedOption, setSelectedOption] = useState(1);
  const [count, setCount] = useState(1);

  const { id } = useParams();
  useEffect(() => {
    fetch(`http://127.0.0.1:8000/shop-product/list/`)
      .then((a) => a.json())
      .then((a) => setProducts(a));
  }, []);
  // const inBasket = basket.find((t)=> t.id ===a.id);
  const product = products.find((a) => a.id === +id);
  const addToBasket = (id, e) => {
    e.preventDefault();
    // console.log("id"+id)
    let check = basket.find((a) => a.id === id);
    if (check) {
      check.count = count;
      dispatch({
        type: "SET_BASKET",
        payload: [...basket],
      });
      return;
    }
    dispatch({
      type: "SET_BASKET",
      payload: [...basket, { id: id, count: count }],
    });
    localStorage.setItem(
      "basket",
      JSON.stringify([...basket, { id: id, count: count }])
    );
    setCount(1);
  };

  const addToFavoriteBasket = (id, e) => {
    e.preventDefault();
    // console.log("id"+id)
    let check = favorite.find((a) => a.id === id);
    if (check) {
      check.count = count;
      dispatch({
        type: "SET_FAVORITE",
        payload: [...favorite],
      });
      return;
    }
    dispatch({
      type: "SET_FAVORITE",
      payload: [...favorite, { id: id, count: count }],
    });
    localStorage.setItem(
      "favorite",
      JSON.stringify([...favorite, { id: id, count: count }])
    );
    setCount(1);
  };

  return products.length ? (
    <>
      <section className="shop_single_banner full-container">
        <h1 className="shop_single_title">Shop</h1>
      </section>

      <section className="single_shop_main ">
        <div className="container">
        <div data-aos="fade-up" className="single_shop_products">
          <div className="single_product">
            <div className="shop_single_product_tag_favorite">
              <div className="shop_single_product_tag">
              <p>{product.category}</p>
            </div>
            <div onClick={(e) => addToFavoriteBasket(product.id, e)} className="shop_single_product_favorite">
            <i class="fa-brands fa-gratipay"></i>
            </div>
            </div>
            
            <a className="shop_single_product_images">
              <img src={product.image} />
            </a>
          </div>
          <div className="single_product_content">
            <a className="shop_single_product_name">{product.name}</a>
            <div className="shop_single_product_pricing_rating">
              <div className="shop_single_product_rating">
                <img src="static/stars.svg" />
              </div>
              <div className="shop_single_product_pricing">
                <div className="shop_single_old_price">${product.oldprice}</div>
                <div className="shop_single_new_price">${product.newprice}</div>
              </div>
            </div>
            <p className="single_product_content_text">
              {product.text}
            </p>

            <form className="commerce_quantity_card">
              <div className="shop_quantity">
                <label className="quantity_text" htmlFor="quantity">
                  Quantity:
                </label>
                <input
                  type="number"
                  id="quantity"
                  min="1"
                  value={count}
                  onChange={(e) => setCount(e.target.value)}
                />
              </div>
              <div className="shop_card">
                <button
                  onClick={(e) => addToBasket(product.id, e)}
                  className="blue_btn"
                >
                  <p>Add To Cart</p>
                  <i className="fa-solid fa-circle-arrow-right"></i>
                </button>
              </div>
            </form>
          </div>
        </div>

        <div data-aos="fade-up" className="product_information">
          <div className="product_des_info">
            {/* <input
              type="radio"
              classNameName="radioclassName radiopd"
              id="pd"
              name="single_product_additional"
            /> */}
            <div
              onClick={() => setSelectedOption(1)}
              className="product_description"
              id={selectedOption === 1 ? "selected__option" : ""}
              htmlFor="pd"
            >
              Product Description
            </div>
            {/* <input
              type="radio"
              classNameName="radioclassName radioai"
              id="ai"
              name="single_product_additional"
            /> */}
            <div
              onClick={() => setSelectedOption(2)}
              className="add_info"
              id={selectedOption === 2 ? "selected__option" : ""}
              htmlFor="ai"
            >
              Additional Info
            </div>
          </div>
          {selectedOption === 1 ? (
            <p className="product_description_text">
            {product.description_text}
            </p>
          ) : (
            <p className="additional_info_text">
              {product.additional_text}
            </p>
          )}
        </div>
        </div>
      </section>

      <section data-aos="fade-up" className="related_products_main ">
        <div className="container">
        <h1 className="shop_single_title">Related Products</h1>
        <div className="related_products">
          {products
            .filter((a) => a.id !== product.id)
            .slice(0, 4)
            .map((a) => (
              <Product data={a} key={a.id} onClick={() => countSet()} />
            ))}
        </div>
        </div>
      </section>
    </>
  ) : null;
}
const t = (a) => a;
export default connect(t)(Shop_single);