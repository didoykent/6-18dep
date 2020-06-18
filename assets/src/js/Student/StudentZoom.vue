<template>
  <div class="iframe-container">
    <meta charset="utf-8">


    <link type="text/css" rel="stylesheet" href="node_modules/@zoomus/websdk/dist/css/bootstrap.css" />
<link type="text/css" rel="stylesheet" href="node_modules/@zoomus/websdk/dist/css/react-select.css" />

    <meta name="format-detection" content="telephone=no">
  </div>
</template>
<script>

import axios from 'axios'
import { ZoomMtg } from '@zoomus/websdk';


console.log("checkSystemRequirements");
console.log(JSON.stringify(ZoomMtg.checkSystemRequirements()));
ZoomMtg.setZoomJSLib('https://dmogdx0jrul3u.cloudfront.net/1.7.7/lib', '/av')
ZoomMtg.preLoadWasm();
ZoomMtg.prepareJssdk();
var API_KEY = "OYfYnfotR7CY75ve-OpVXw";
var API_SECRET = "w0XvAh4gzAsaQWqPi0dURDloRqn55iAGP0Dk";
export default {

  data() {
    return {

      meetConfig: {},
      signature: {},
      meetingId: "6220784534"
    };
  },

  created: function() {


    console.log(this.$route.params)

    if(this.$route.params.tutor_data && this.$route.params.class_data){

      const tutorData  = this.$route.params.tutor_data

      const classData = this.$route.params.class_data

      const form = new FormData()

      form.append('tutorData', tutorData)
      form.append('classData', classData)

      axios.post('Uedu/generate_student_signature', form).then(res => {

        console.log(res.data, 'data')


        if(res.data){
    const config = JSON.parse(res.data.substr(1))
          this.meetConfig = {
            apiKey: config.apiKey,
            apiSecret: config.apiSecret,
            meetingNumber: parseInt(config.meetingNumber, 10),
            userName: config.userName,
            passWord: config.password,
            leaveUrl: "https://zoom.us",
            role: parseInt(config.role, 10),
          };

          console.log(config, 'data')



          this.signature = config.signature

          console.log(this.meetConfig.meetingNumber)
          console.log(this.meetConfig.userName)
          console.log(this.signature)
          console.log(this.meetConfig.apiKey)
          console.log(this.meetConfig.passWord)
          ZoomMtg.init({
            leaveUrl: "http://www.zoom.us",
            isSupportAV: true,
            success: () => {
              ZoomMtg.join({
                meetingNumber: this.meetConfig.meetingNumber,
                userName: this.meetConfig.userName,
                signature: this.signature,
                apiKey: this.meetConfig.apiKey,

                passWord: this.meetConfig.passWord,
                success: function(res) {

                  console.log("join meeting success");
                },
                error: function(res) {

                  console.log(res, 'res');
                }
              });
            },
            error: function(res) {

              console.log(res, 'err');
            }
          });


        }
      }).catch(err => {

        console.log(err)
      })
    }




  },

  methods: {


joinMeeting(){

        // Meeting config object



        // Generate Signature function

        // join function

      }
  },
  mounted: function() {}
};
</script>


<style>

#zmmtg-root{


  position: relative;

  background-color: transparent;
}
</style>
