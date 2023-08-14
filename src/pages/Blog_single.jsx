import { useState, useEffect } from "react"
import { useParams } from "react-router-dom"
import React from "react"
function Blog_single() {
    const {id}=useParams();
    const [data,setData]=useState([])
    useEffect(()=>{
        fetch(`http://127.0.0.1:8000/blogs/detail/${id}`)
        .then((a)=>a.json ())
        .then((a)=> setData(a))
    },[])
    // const date=data.created_at.getDay()
    console.log(data)

  return (
    <>
     
        <section className="blog_single_first position full-container">
            <img src={data.image}/>
            <div className ="blog_single_prds">
                <div className ="blog_single_prd">
                    <div className="blog_single_info">
                    <h3>Posted On: <span className="p"> {data.created_at_display}</span></h3>
                        <div className="flex">
                            <i className="fa-solid fa-user"></i>
                            <p className="p"> {data.writer}</p>
                        </div>
                    </div>
                    <div className="blog_research">
                        <h2 className="h2">{data.header}</h2>
                        {/* summary */}
                          <p className="p">{data.summary}</p>
                    </div>
                </div>
            </div>
        </section>
    

     <section className="blog_empty"></section>
    <section className="blog_single_second">
        <div className="blog_single_container">
{/*             
            <h2>{data.title}</h2>
            <p className="p">{data.context}</p> */}

            <h2>{data.titlefirst}</h2>
            <p className="p">{data.contextfirst}</p>
                   
            <h2>{data.titlesecond}</h2>
            <p className="p">{data.contextsecond}</p>

            {/* <h2>{data.titlethird}</h2>
            <p className="p">{data.contextthird}</p> */}

        </div >
    </section >
    </>
  )
}

export default Blog_single