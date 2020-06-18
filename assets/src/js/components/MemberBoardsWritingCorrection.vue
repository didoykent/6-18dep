<template>
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
            Writing Correction
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
              <template v-for="(item, index) in writingCorrections">
                <v-list-item :key="item.correction_id" @click = "setCorrection(item)">
                  <template>
                    <v-tooltip bottom>
                      <template v-slot:activator="{ on }">
                        <v-list-item-avatar>
                          <v-icon v-on="on" x-large color="#e91e63">mdi-alpha-a-circle</v-icon>
                        </v-list-item-avatar>
                      </template>

                    </v-tooltip>
                    <v-list-item-content>
                      <v-list-item-title v-text="item.studentname"></v-list-item-title>
                      <v-list-item-subtitle class="text--primary" v-text="item.subject"></v-list-item-subtitle>
                      <v-list-item-subtitle v-text="item.content"></v-list-item-subtitle>
                    </v-list-item-content>

                    <v-list-item-action>
                      <v-list-item-action-text v-text="getTimeDiff(item.sentDate)"></v-list-item-action-text>
                    </v-list-item-action>
                  </template>
                </v-list-item>

                <v-divider v-if="index < writingCorrections.length" :key="index"></v-divider>
              </template>
            </v-list-item-group>
          </v-list>

          <v-container>

          </v-container>




        </v-card>
      </v-col>
    </v-row>

  </div>

  <v-dialog v-model="writeDialog" max-width="1000" max-height="500">
          <v-card>
            <v-card-title class="headline">
              <div class="d-flex justify-content-center align-items-center mr-2" style="height:50px;width:50px;
              background-color:#e91e63;">
              <v-icon color="white" x-large>create</v-icon>
            </div>
              Write
            </v-card-title>
            <v-container fluid>
              <v-row>
                <v-col cols="12" sm="3">
                    <v-text-field  disabled v-model="selectedContent['studentname']" label="Student"></v-text-field>
                </v-col>
                <v-col cols="12" sm="9">
                    <v-text-field  disabled v-model="selectedContent['subject']" label="Subject"></v-text-field>
                </v-col>
              </v-row>
              <v-row>
                <v-col cols="12">
                  <p style="background-color:#F0F0F0" class="subtitle-1">{{selectedContent['content']}}</p>
                </v-col>

                <v-col cols="12" class="mb-4" v-if ="!selectedContent['corrected']">
                  <v-textarea  v-model="writingCorrection"></v-textarea>
                </v-col>


                <v-col cols="12" class="mb-4" v-else>
                <p>{{selectedContent['correctedContent']}}</p>
                </v-col>
              </v-row>


              <v-row class="d-flex justify-content-end">
                <v-btn text style="color:#1976d2" @click="writeDialog = false">Cancel</v-btn>
                <v-btn color="#e91e63" class="white--text mx-2"  v-if = "!selectedContent['corrected']"@click = "set_content_correction()">Reply</v-btn>
              </v-row>
            </v-container>
          </v-card>
        </v-dialog>
</v-container>
</template>

<script>

import moment from 'moment'
import axios from 'axios'
export default {


  data: () => ({
    selectedContent: '',
    writingCorrection: '',
    writingCorrections: [],
    writeDialog: false,
    selected: [2],
    items: [{
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

this.getTutorCorrection()
},

methods:{

  async getTutorCorrection(){

    await axios.get('Correction/getTutorCorrection').then(res => {

      if(res.data){

        this.$set(this.$data, 'writingCorrections', res.data)

        this.writingCorrections.reverse()
      }
    })
  },

  getTimeDiff(sentDate){

    return moment(sentDate).fromNow();
  },

  setCorrection(item){

    console.log(item, 'item1')
    this.selectedContent = item
    this.writeDialog = true

  },

  set_content_correction(){

    if(this.writingCorrection && this.selectedContent){

       this.selectedContent.correctedContent = this.writingCorrection
       this.selectedContent.corrected = true

       const writing_correction = this.selectedContent

       const form = new FormData()

       form.append('contentCorrection', JSON.stringify(writing_correction))

       axios.post('Correction/set_content_correction', form).then(res => {

    if(res.data.success) {


        this.$socket.emit('set_content_correction', writing_correction)
        location.reload()
    }
       })







    }
  }
},

sockets: {

  tutor_writing_correction(data){
    if(data){
    this.writingCorrections.unshift(data)
  }
    console.log(data, 'data')
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
