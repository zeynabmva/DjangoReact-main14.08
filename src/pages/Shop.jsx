import React, { useEffect, useState } from "react";

import Product from "../components/Product";
import Pagination from "../components/Pagination";
function Shop() {
  const [products, setProducts] = useState([]);
  useEffect(() => {
    fetch("http://127.0.0.1:8000/shop-product/list/")
      .then((a) => a.json())
      .then((a) => setProducts(a));
  }, []);

  const [type, setType] = useState("");
  const [cat, setCat] = useState("all");
  const [minValue, setMinValue] = useState(0);
  const [maxValue, setMaxValue] = useState(1000);
  const [minCalories, setMinCalories] = useState(0);
  const [maxCalories, setMaxCalories] = useState(1000);
  const [page, setPage] = useState(1);
  const itemPerPage = 8;

  // const [activePage, setActivePage] = useState(1);
  // const productPerPage = 4;
  // const totalPageCount = Math.ceil(products.length / productPerPage);
  // if (activePage > totalPageCount) {
  //   setActivePage(totalPageCount);
  // }
  // if (!activePage && totalPageCount > 0) {
  //   setActivePage(1);
  // }
  // const start = (activePage - 1) * productPerPage;

  // const end = start + productPerPage;

  const handleType = (e) => {
    setType(e.target.value);
  };

  useEffect(() => {
    if (type === "EC") {
      setProducts([...products].sort((a, b) => a.newprice - b.newprice));
    } else if (type === "CE") {
      setProducts([...products].sort((a, b) => b.newprice - a.newprice));
    } else if (type === "AZ") {
      setProducts([
        ...products.sort((a, b) => a.name.charCodeAt() - b.name.charCodeAt()),
      ]);
    } else if (type === "ZA") {
      setProducts([
        ...products.sort((a, b) => b.name.charCodeAt() - a.name.charCodeAt()),
      ]);
    }
  }, [type]);

  return (
    <section className="shop_bigsection_bg">
      <section className="shop_banner full-container"></section>
      <section className="shop_main container">
        <div className="all_filters_section">
          <div className="category_filters">
            <button onClick={() => setCat("all")}>All</button>
            <button onClick={() => setCat("Vegetable")}>Vegetable</button>
            <button onClick={() => setCat("Fresh")}>Fresh</button>
            <button onClick={() => setCat("Health")}>Health</button>
            <button onClick={() => setCat("Nuts")}>Nuts</button>
            <button onClick={() => setCat("Millets")}>Millets</button>
          </div>

          <div className="filter_select">
            <select onChange={handleType}>
              <option value={"CE"}>Price (lowest)</option>
              <option value={"EC"}>Price (highest)</option>
              <option value={"AZ"}>Name (A-Z)</option>
              <option value={"ZA"}>Name(Z-A)</option>
            </select>
          </div>
          <div className="filter_price_calories">
            <div className="price_filter ">
              <label htmlFor="min_price">Min Price:</label>

              <input
                type="number"
                className="price_slider"
                id="min_price"
                value={minValue}
                onClick={(e) => (e.target.value = "")}
                onChange={(e) => {
                  setMinValue(+e.target.value);
                }}
              />

              <label htmlFor="max_price">Max Price:</label>
              <input
                type="number"
                className="price_slider"
                id="max_price"
                value={maxValue}
                onClick={(e) => (e.target.value = "")}
                onChange={(e) => {
                  setMaxValue(+e.target.value);
                }}
              />
            </div>

            <div className="calories_filter ">
              <label htmlFor="min_calories">Min Calories:</label>

              <input
                type="number"
                className="price_slider"
                id="min_calories"
                value={minCalories}
                onClick={(e) => (e.target.value = "")}
                onChange={(e) => {
                  setMinCalories(+e.target.value);
                }}
              />

              <label htmlFor="max_calories">Max Calories:</label>
              <input
                type="number"
                className="price_slider"
                id="max_calories"
                value={maxCalories}
                onClick={(e) => (e.target.value = "")}
                onChange={(e) => {
                  setMaxCalories(+e.target.value);
                }}
              />
            </div>

            {/* <div className="calories_filter ">
              <label htmlFor="calories">Calories:</label>

              <input
                type="number"
                // min={filters.min}
                // max={filters.max}
                className="price_slider"
                id="caloires"
              />
            </div> */}
          </div>
        </div>
        <div data-aos="fade-up" className="shop_products">
          {cat === "all"
            ? [...products]
                .slice(
                  itemPerPage * (page - 1),
                  itemPerPage * (page - 1) + itemPerPage
                )
                .filter((a) => a.newprice >= minValue && a.newprice <= maxValue)
                .filter(
                  (a) => a.calories >= minCalories && a.calories <= maxCalories
                )
                .map((a) => <Product data={a} key={a.id} />)
            : [...products]
                .filter((a) => a.newprice >= minValue && a.newprice <= maxValue)
                .filter(
                  (a) => a.calories >= minCalories && a.calories <= maxCalories
                )
                .filter((a) => a.category === cat)
                .map((a) => <Product data={a} key={a.id} />)}
        </div>

        <div className="pag">
          {cat === "all" ? (
            <Pagination
              setPage={setPage}
              page={page}
              itemCount={products.length}
              itemPerPage={itemPerPage}
            />
          ) : (
            <div></div>
          )}
        </div>
      </section>
    </section>
  );
}

export default Shop;
