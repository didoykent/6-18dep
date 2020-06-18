<template>

  <div>

    <TutorNavbar></TutorNavbar>
  <v-container fluid>
    <div class="d-flex flex-row justify-space-between">
      <v-row justify="center">
        <v-col cols="12">
          <v-card>
            <v-card-title class="headline">
              <div class="d-flex justify-content-center align-items-center mr-2" style="height:50px;width:50px;
              background-color:#e91e63;">
              <v-icon color="white" x-large>spellcheck</v-icon>
            </div>
          Announcements
          </v-card-title>
          <v-container fluid>
            <v-row>
              <v-col cols="12" sm="3">
                <v-text-field label="Search" v-model="search" outlined></v-text-field>
              </v-col>
            </v-row>
          </v-container>
          <v-divider></v-divider>

    <v-list two-line>
      <v-list-item-group>
        <template v-for="(item, index) in Announcements">
          <v-list-item :key="item.announcement_id" >
            <template>
              <v-list-item-avatar>
                <v-icon x-large color="#E91E63">mdi-alpha-{{item.announcer.charAt(0).toLowerCase()}}-circle</v-icon>
              </v-list-item-avatar>
              <v-list-item-content @click="viewAnnouncement(item)">
                <v-list-item-title v-text="item.announcer"></v-list-item-title>
                <v-list-item-subtitle class="text--primary" v-text="item.subject"></v-list-item-subtitle>
                <v-list-item-subtitle v-text="item.content"></v-list-item-subtitle>
              </v-list-item-content>

              <v-list-item-action>
                <v-list-item-action-text v-text="item.updated_at"></v-list-item-action-text>
              </v-list-item-action>
            </template>
          </v-list-item>

          <v-divider
            v-if="index < Announcements.length"
            :key="index"
          ></v-divider>
        </template>
      </v-list-item-group>
    </v-list>
    </v-card>
    </v-col>
  </v-row>
  </div>
  </v-container>

  <v-dialog v-model="viewAnnouncementDialog" max-width="1000" max-height="500">
    <v-card>
      <v-card-title class="headline">
        <div class="d-flex justify-content-center align-items-center mr-2" style="height:50px;width:50px;
        background-color:#E91E63;">
        <v-icon color="white" x-large>create</v-icon>
      </div>


      <span>All Tutor Announcement</span>
      </v-card-title>
      <v-container fluid>
        <v-row>
          <v-col cols="12">
              <p class="subtitle-1 font-weight-regular">Name: {{selectedAnnouncement['announcer']}}</p>
          </v-col>
        </v-row>
        <v-row>
          <v-col cols="12">
            <p class="subtitle-1 font-weight-regular">Subject: {{selectedAnnouncement['subject']}}</p>
          </v-col>
        </v-row>
        <v-row>
          <v-col cols="12">
            <p class="subtitle-1 font-weight-regular">{{selectedAnnouncement['content']}}</p>
          </v-col>
        </v-row>
        <v-row class="d-flex justify-content-end">
          <v-btn color="#E91E63" class="white--text mx-2" @click = "viewAnnouncementDialog = false" >Close</v-btn>
        </v-row>
      </v-container>
    </v-card>
  </v-dialog>

  </div>

</template>

<script>
import axios from 'axios'

import TutorNavbar from './TutorNavbar.vue'
export default {

  components: {TutorNavbar},

  data(){

    return {

Announcements: [],
viewAnnouncementDialog: false,
selectedAnnouncement: '',
    }
  },

  mounted(){



      const form = new FormData()
      form.append('category', 'ALL TUTOR')
    axios.post('Announcement/getAnnouncement', form).then(res => {

      if(res.data.announcements){

        this.$set(this.$data, 'Announcements', res.data.announcements)

      }
      else{

          this.Announcements = []
      }
        console.log(this.Announcements, 'ann')
    })

  },

  methods: {

    viewAnnouncement(item){

      console.log(item, 'item')

          if(item) {

            this.selectedAnnouncement = item




          this.viewAnnouncementDialog  = true


    }
  },

},

}
</script>

<style lang="css" scoped>
</style>
