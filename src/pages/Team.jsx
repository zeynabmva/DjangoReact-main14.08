import { useState, useEffect } from "react"
import React from "react"
function Team() {
    const [data, setData] = useState([])
    useEffect(() => {
        fetch(`http://127.0.0.1:8000/team/list/`)
            .then((a) => a.json())
            .then((a) => setData(a))
    }, [])
     
    return (
        <>
            <section className="team_first full-container"></section>
            <section className="about_fourth team_fourth">
                <div className="container">
                    <div className="about_center">
                        <h4 className="h4">Team</h4>
                        <h2 className="h2">Our Organic Experts</h2>
                        <p className="p">We have grown on the principles of health, ecology, and care. We aim to give our customers a healthy chemical-free meal for perfect nutrition.</p>
                    </div>
                    <div className="team_experts">
                        {data.map((a) => (
                            <div className="team_expert">
                                <div className="team_expert_img">
                                    <img src={a.image}></img>
                                </div>
                                <div className="team_expert_infos">
                                    <h2 className="about_blue">{a.name}</h2>
                                    <div className="about_expert_infoss">
                                        <h4 className="h4">{a.profession}</h4>
                                        <div className="about_info_i">
                                            {a.facebook && <a href={a.facebook}><img src="/static/facebook.png" alt="Facebook"></img></a>}
                                            {a.twitter && <a href={a.twitter}><img src="/static/twitter.png" alt="Twitter"></img></a>}
                                            {a.instagram && <a href={a.instagram}><img src="/static/Insta.png" alt="Instagram"></img></a>}
                                        </div>
                                    </div>
                                </div>
                            </div>
                        ))}


                    </div>
                </div>
            </section>
        </>
    )
}

export default Team