<template>
  <v-container fluid>
    <div class="d-flex flex-row justify-space-between">
    	<v-row justify="center">
        <v-col cols="12" md="11">
          <v-card>
            <v-card-title class="headline">
              <div class="d-flex justify-content-center align-items-center mr-2" style="height:50px;width:50px;
              background-color:#E91E63;">
              <v-icon color="white" x-large>announcement</v-icon>
            </div>
              Announcements
            </v-card-title>
            <v-divider></v-divider>
            <v-container class="px-4">
              <v-tabs class="" @click="selectedTab($event)">
                <v-tab  @click="selectedTab($event)" class="title font-weight-regular mx-4">KR ADMIN</v-tab>
                <v-tab  @click="selectedTab($event)" class="title font-weight-regular">ALL ADMIN</v-tab>
                <v-tab  @click="selectedTab($event)" class="title font-weight-regular">ALL TUTOR</v-tab>
                <v-tab-item>
                  <v-list two-line>
                    <v-list-item-group>
                      <template v-for="(item, index) in Announcements">
                        <v-list-item :key="item.announcement_id" v-if = "item.category === 'KR ADMIN'">
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
                  <v-container>
                    <v-row justify="end">
                      <v-col align-self="end" cols="1">
                        <v-btn @click="checkWrite()" color="#E91E63" class="white--text">WRITE</v-btn>
                      </v-col>
                    </v-row>
                  </v-container>
                </v-tab-item>
                <v-tab-item>
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
                  <v-container>
                    <v-row justify="end">
                      <v-col align-self="end" cols="1">
                        <v-btn @click="checkWrite()" color="#E91E63" class="white--text">WRITE</v-btn>
                      </v-col>
                    </v-row>
                  </v-container>
                </v-tab-item>
                <v-tab-item>
                  <v-list two-line>
                    <v-list-item-group>
                      <template v-for="(item, index) in Announcements">
                        <v-list-item :key="item.announcement_id">
                          <template v-for="(item, index) in Announcements">
                            <v-list-item :key="item.announcement_id">
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
                        </v-list-item>

                        <v-divider
                          v-if="index < Announcements.length"
                          :key="index"
                        ></v-divider>
                      </template>
                    </v-list-item-group>
                  </v-list>
                  <v-container>
                    <v-row justify="end">
                      <v-col align-self="end" cols="1">
                        <v-btn @click="checkWrite()" color="#E91E63" class="white--text">WRITE</v-btn>
                      </v-col>
                    </v-row>
                  </v-container>
                </v-tab-item>
              </v-tabs>
            </v-container>

          </v-card>
        </v-col>
    	</v-row>

      <div class="float-right button-container" >
        <div class="buttons">
            <v-row class="ma-2 mb-4">
              <button class="float-right ml-2 v-btn v-btn--depressed theme--light" style="background-color:#E91E63" icon>
                <v-icon color="white" x-large>question_answer</v-icon>
              </button>
            </v-row>
          </div>
      </div>

      <v-dialog v-model="writeDialog" max-width="1000" max-height="500">
        <v-card>
          <v-card-title class="headline">
            <div class="d-flex justify-content-center align-items-center mr-2" style="height:50px;width:50px;
            background-color:#E91E63;">
            <v-icon color="white" x-large>announcement</v-icon>
          </div>
            <span v-if="currentTab == 'KR ADMIN'">KR Admin Announcement</span>
            <span v-if="currentTab == 'ALL ADMIN'">All Admin Announcement</span>
            <span v-if="currentTab == 'ALL TUTOR'">All Tutor Announcement</span>
          </v-card-title>
          <v-container fluid>
            <v-row>
              <v-col cols="12">
                  <v-text-field v-model="Content.subject" label="Subject"></v-text-field>
              </v-col>
            </v-row>
            <v-row>
              <v-col cols="12">
                <v-textarea filled placeholder="Write here ..." v-model="Content.content"></v-textarea>
              </v-col>
            </v-row>
            <v-row class="d-flex justify-content-end">
              <v-btn text style="color:#E91E63" @click="writeDialog = false">Close</v-btn>
              <v-btn color="#E91E63" class="white--text mx-2" @click = "createAnnouncement()">Post</v-btn>
            </v-row>
          </v-container>
        </v-card>
      </v-dialog>

      <v-dialog v-model="viewAnnouncementDialog" max-width="1000" max-height="500">
        <v-card>
          <v-card-title class="headline">
            <div class="d-flex justify-content-center align-items-center mr-2" style="height:50px;width:50px;
            background-color:#E91E63;">
            <v-icon color="white" x-large>create</v-icon>
          </div>
          <span v-if="currentTab == 'KR ADMIN'">KR Admin Announcement</span>
          <span v-if="currentTab == 'ALL ADMIN'">All Admin Announcement</span>
          <span v-if="currentTab == 'ALL TUTOR'">All Tutor Announcement</span>
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
              <v-btn color="#E91E63" class="white--text mx-2" @click="viewAnnouncementDialog = false">Close</v-btn>
            </v-row>
          </v-container>
        </v-card>
      </v-dialog>

      <v-dialog v-model="ownerViewAnnouncementDialog" max-width="1000" max-height="500">
        <v-card>
          <v-card-title class="headline">
            <div class="d-flex justify-content-center align-items-center mr-2" style="height:50px;width:50px;
            background-color:#E91E63;">
            <v-icon color="white" x-large>create</v-icon>
          </div>
          <span v-if="currentTab == 'KR ADMIN'">KR Admin Announcement</span>
          <span v-if="currentTab == 'ALL ADMIN'">All Admin Announcement</span>
          <span v-if="currentTab == 'ALL TUTOR'">All Tutor Announcement</span>
          </v-card-title>
          <v-container fluid>
            <v-row>
              <v-col cols="12">
                  <v-text-field label="From" disabled v-model="selectedAnnouncement['announcer']"></v-text-field>
              </v-col>
            </v-row>
            <v-row>
              <v-col cols="12">
                <v-text-field label="Subject" v-model="selectedAnnouncement['subject']"></v-text-field>
              </v-col>
            </v-row>
            <v-row>
              <v-col cols="12">
                <v-textarea label="Announcement" v-model="selectedAnnouncement['content']"></v-textarea>
              </v-col>
            </v-row>
            <v-row class="d-flex justify-content-end">
                <v-btn style="background-color:#F0F0F0;color:#E91E63" class="mx-2" @click = "deleteAnnouncement()">Delete</v-btn>
                <v-btn style="color:#E91E63" outlined class="mx-2"  @click="ownerViewAnnouncementDialog = false">Close</v-btn>
                <v-btn color="#E91E63" class="white--text mx-2" @click = "editAnnouncement()">Edit</v-btn>
            </v-row>
          </v-container>
        </v-card>
      </v-dialog>

    </div>
  </v-container>
</template>

<script>
import moment from 'moment'
import axios from 'axios'
export default {
  data: () => ({
      User: '',
      selectedAnnouncement: '',
      Content: [],
      Announcements: [],
      selected: [2],
      writeDialog: false,
      viewAnnouncementDialog: false,
      ownerViewAnnouncementDialog: false,
      currentTab: 'KR ADMIN',

      from: 'Name',
      subject: 'Subject',
      writeAnnouncement: 'Lorem ipsum dolor sit amet, integer sed eros urna, ipsum fermentum cursus sit massa nullam et, ut et elit at. Ultrices eleifend scelerisque. Molestie at massa morbi ullamcorper, sit duis, lacus non magna, ante quam, non augue sit est. Neque urna justo conubia congue vitae, mauris et amet augue urna diam. Curabitur massa elit, fringilla dolore posuere venenatis, curabitur etiam imperdiet non eu integer, mauris nullam et dolor. Blandit ullamcorper, vel consectetuer turpis mauris, vel enim donec, id leo leo urna facilisi. Imperdiet laoreet tempor cubilia amet, adipiscing condimentum, diam consectetuer, amet in neque dolor dui pellentesque, diam lacus risus lacinia quis vitae.',
      from1: 'Name',
      subject1: 'Subject',
      writeAnnouncement1: 'Lorem ipsum dolor sit amet, integer sed eros urna, ipsum fermentum cursus sit massa nullam et, ut et elit at. Ultrices eleifend scelerisque. Molestie at massa morbi ullamcorper, sit duis, lacus non magna, ante quam, non augue sit est. Neque urna justo conubia congue vitae, mauris et amet augue urna diam. Curabitur massa elit, fringilla dolore posuere venenatis, curabitur etiam imperdiet non eu integer, mauris nullam et dolor. Blandit ullamcorper, vel consectetuer turpis mauris, vel enim donec, id leo leo urna facilisi. Imperdiet laoreet tempor cubilia amet, adipiscing condimentum, diam consectetuer, amet in neque dolor dui pellentesque, diam lacus risus lacinia quis vitae.',



      items: [
        {
          action: '15 min',
          headline: 'Brunch this weekend?',
          title: 'Ali Connors',
          subtitle: "I'll be in your neighborhood doing errands this weekend. Do you want to hang out?",
        },
        {
          action: '2 hr',
          headline: 'Summer BBQ',
          title: 'me, Scrott, Jennifer',
          subtitle: "Wish I could come, but I'm out of town this weekend.",
        },
        {
          action: '6 hr',
          headline: 'Oui oui',
          title: 'Sandra Adams',
          subtitle: 'Do you have Paris recommendations? Have you ever been?',
        },
        {
          action: '12 hr',
          headline: 'Birthday gift',
          title: 'Trevor Hansen',
          subtitle: 'Have any ideas about what we should get Heidi for her birthday?',
        },
        {
          action: '18hr',
          headline: 'Recipe to try',
          title: 'Britta Holt',
          subtitle: 'We should eat this: Grate, Squash, Corn, and tomatillo Tacos.',
        },
      ],
    }),


    mounted(){

      if(this.currentTab){

        const form = new FormData()
        form.append('category', this.currentTab)
      axios.post('Announcement/getAnnouncement', form).then(res => {

        if(res.data.announcements){

          this.$set(this.$data, 'Announcements', res.data.announcements)
          this.$set(this.$data, 'User', res.data.user)
        }
        else{

            this.Announcements = []
        }
          console.log(res.data)
      })
      }
    },

    methods: {
      selectedTab(event){
        const selectedTab = event.target.innerText
        if(selectedTab == 'KR ADMIN'){
          this.currentTab = 'KR ADMIN'
        }else if(selectedTab == 'ALL ADMIN'){
          this.currentTab = 'ALL ADMIN'
        }else if(selectedTab == 'ALL TUTOR'){
          this.currentTab = 'ALL TUTOR'
        }

        if(this.currentTab){

          const form = new FormData()
          form.append('category', this.currentTab)
        axios.post('Announcement/getAnnouncement', form).then(res => {
          if(res.data.announcements){

            this.$set(this.$data, 'Announcements', res.data.announcements)
          }

          else{

                this.Announcements = []
          }
            console.log(res.data)
        })
        }
      },

      checkWrite(){

          console.log(this.User)
            console.log(  this.currentTab, 'tab')
      if(  this.currentTab === 'KR ADMIN' && this.User.position === 'Kr_manager'){


        this.writeDialog = true

      }

      if(  this.currentTab === 'ALL ADMIN' && this.User.position === 'Kr_manager'){


    this.writeDialog = true

  }

  if(  this.currentTab === 'ALL TUTOR' && this.User.position !== 'Team_leader' &&  this.User.position !== 'Assistant_team_leader' && this.User.position !== 'Tutor' && this.User.position !== 'Trainee' && this.User.position !== 'Student'){


this.writeDialog = true

}
      },

      getTimeDiff(sentDate){

        return moment(sentDate).fromNow();
      },

      createAnnouncement(){

        if(this.currentTab && this.Content){

            const subject = this.Content.subject
            const content = this.Content.content
            const category = this.currentTab

            const form = new FormData()

            form.append('subject', subject)
            form.append('content', content)
            form.append('category', category)

            axios.post('Announcement/addAnnouncement', form).then(res => {
              if(res.data.error === false){

              location.reload()
              }
              console.log(res.data, 'res')
            })


        }
      },

      viewAnnouncement(item){

        console.log(item, 'item')
        console.log(this.User, 'user')
            if(item && this.User){

              this.selectedAnnouncement = item
        if(item.announcer_idx === this.User.idx){

            this.ownerViewAnnouncementDialog = true
        }

        else{

            this.viewAnnouncementDialog  = true
        }

      }
    },

    editAnnouncement(){

        if(this.selectedAnnouncement){

          const subject = this.selectedAnnouncement.subject
          const content  = this.selectedAnnouncement.content
          const category  = this.selectedAnnouncement.category
          const announcement_id =  this.selectedAnnouncement.announcement_id

          const form = new FormData()

          form.append('subject', subject)
          form.append('content', content)
          form.append('category', category)
          form.append('announcement_id', announcement_id)

          axios.post('Announcement/updateAnnouncement', form).then(res => {

                  if(res.data.error === false){

                    location.reload()
                  }
            console.log(res.data, 'edit')
          })
        }
    },

    deleteAnnouncement(){

        if(this.selectedAnnouncement){


  const announcement_id =  this.selectedAnnouncement.announcement_id

        const form = new FormData()

          form.append('announcement_id', announcement_id)

          axios.post('Announcement/deleteAnnouncement', form).then(res => {

            if(res.data.error === false){

              location.reload()
            }

            console.log(res.data, 'delete')
          })
        }
    }
    }
}
</script>

<style lang="css">

.button-container {
  width: 50px;
  position: relative;
}

.buttons {
  margin: 0;
  position: absolute;
  top: 50%;
  -ms-transform: translateY(-50%);
  transform: translateY(-50%);
}

</style>
