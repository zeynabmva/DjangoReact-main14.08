import React from 'react'

function Video({ videoShown, setVideoShown }) {
    return (
        <div className='video_modal'>
            <div className='video_inner'>
                <span onClick={() => setVideoShown(!videoShown)} className="close_video">
                    &times;
                </span>
                <iframe src="https://www.youtube.com/embed/7Dxu97R077w" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" allowfullscreen></iframe>
            </div>
        </div>
    )
}

export default Video