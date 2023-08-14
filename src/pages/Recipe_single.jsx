import { useParams } from "react-router-dom"
import React from "react"
import {useEffect, useState} from "react"
function Recipe_single() {
    const {id}=useParams()
    const [data,setData]=useState([])
    const [data1, setData1] = useState([])
    useEffect(() => {
        const fetchData = async () => {
            try {
                const response = await fetch(`http://127.0.0.1:8000/recipes/detail/${id}`);
                const data = await response.json();
                const response1 = await fetch('http://127.0.0.1:8000/shop-product/list/');
                const data1 = await response1.json();
                setData1(data1);
                setData(data);
            } catch (error) {
                console.error('Error fetching data:', error);

            }
        };

        fetchData();
    }, [])

 
  return (
    <>
          <section style={{backgroundImage: `url("${data.image}")`}} className="portfolio_single_first position full-container">
                <div key={data.id} className="portfolio_single_prds">
                        <div className="portfolio_single_prd">
                            <h2 className="h2">{data.name}</h2>
                      <p className="p">{data.summary}</p>
                        </div>
                        <div className="portfolio_single_prd_infos">
                            <div className="portfolio_single_prd_info">
                                <h3 className="h3">Preparation :</h3>
                                <p className="p">{data.preparation}</p>
                            </div>
                            <div className="portfolio_single_prd_info">
                                <h3 className="h3">Cooking :</h3>
                                <p className="p">{data.cooking}</p>
                            </div>
                            <div className="portfolio_single_prd_info">
                                <h3 className="h3">Type :</h3>
                                <p className="p">{data.type}</p>
                            </div>
                            <div className="portfolio_single_prd_info">
                                <h3 className="h3">Services :</h3>
                                <p className="p">{data.services}</p>
                            </div>
                        </div>
                    </div>
            </section>
    
            <section className="portfolio_empty"></section>

            <section className="portfolio_single_second">
                <div className="portfolio_single_container">
                    <h2>Ingredients:</h2>
                  <p className="p">{data.ingredients}</p>
            <div className="portfolio_single_img">
                <img src={data.addition_pic}></img>
                    <p className="p">The Organic Products</p>
            </div>
                  <h2>Instruction: </h2>
                  <p className="p">
                      {data.instructions}
                  </p >
            <h2>Products:</h2>
            
            {data1.map((a)=>{
                return(
                <div key={a.id}>
                    <h2>Hello</h2>
                </div>
                )
                console.log(a.name)
            })}
        </div>
    </section >
    </>
  )
}

export default Recipe_single