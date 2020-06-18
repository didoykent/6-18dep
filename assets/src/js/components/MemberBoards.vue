<template>
  <v-container fluid style="height:100%">
    <v-row class="mt-3 ml-2">
      <v-col cols="12" sm="4" md="2" justify="center" class=" nav px-0">
        <v-btn :style="buttonColor1" block text @click="navClick($event)">Writing Correction</v-btn>
      </v-col>
      <v-divider vertical></v-divider>
      <v-col cols="12" sm="4" md="2" align="center" justify="center" class="nav px-0">
        <v-btn :style="buttonColor2" block text @click="navClick($event)">Announcements</v-btn>
      </v-col>
      <v-divider vertical></v-divider>
      <v-col cols="12" sm="4" md="2" align="center" justify="center" class="nav px-0">
        <v-btn :style="buttonColor3"  block text @click="navClick($event)">Q&A</v-btn>
      </v-col>
      <v-col cols="12" sm="4" md="2" align="center" justify="center" class="nav px-0">
        <v-btn :style="buttonColor4"  block text @click="navClick($event)">FAQ</v-btn>
      </v-col>
    </v-row>
    <v-row style="height:100%" align="stretch">
      <MemberBoardsWritingCorrection v-if="currentComponent === 'MemberBoardsWritingCorrection'"></MemberBoardsWritingCorrection>
      <MemberBoardsAnnouncements v-if="currentComponent === 'MemberBoardsAnnouncements'"></MemberBoardsAnnouncements>
      <MemberBoardsQA v-if="currentComponent === 'MemberBoardsQA'"></MemberBoardsQA>
      <MemberBoardsFAQ v-if="currentComponent === 'MemberBoardsFAQ'"></MemberBoardsFAQ>
    </v-row>
  </v-container>
</template>

<script>
 import MemberBoardsWritingCorrection from './MemberBoardsWritingCorrection'
 import MemberBoardsAnnouncements from './MemberBoardsAnnouncements'
 import MemberBoardsQA from './MemberBoardsQA'
 import MemberBoardsFAQ from './MemberBoardsFAQ'

export default {

  components: {
     MemberBoardsWritingCorrection,
     MemberBoardsAnnouncements,
     MemberBoardsQA,
     MemberBoardsFAQ
  },


  data: vm => ({
    currentComponent: 'MemberBoardsWritingCorrection',
    buttonColor1: '',
    buttonColor2: '',
    buttonColor3: ''
  }),

  mounted(){
    console.log('a')
    if(this.currentComponent == 'MemberBoardsWritingCorrection'){
      this.buttonColor1 = 'background-color:#E91E63;color:white'
      this.buttonColor2 = ''
      this.buttonColor3 = ''
    }
  },

  methods: {
    navClick(selected) {
      if (selected.target.innerText == 'WRITING CORRECTION') {
        this.currentComponent = 'MemberBoardsWritingCorrection'
        this.buttonColor1 = 'background-color:#E91E63;color:white'
        this.buttonColor2 = ''
        this.buttonColor3 = ''
        this.buttonColor4 = ''
      } else if (selected.target.innerText == 'ANNOUNCEMENTS') {
        this.currentComponent = 'MemberBoardsAnnouncements'
        this.buttonColor1 = ''
        this.buttonColor2 = 'background-color:#E91E63;color:white'
        this.buttonColor3 = ''
        this.buttonColor4 = ''
      } else if (selected.target.innerText == 'Q&A') {
        this.currentComponent = 'MemberBoardsQA'
        this.buttonColor1 = ''
        this.buttonColor2 = ''
        this.buttonColor3 = 'background-color:#E91E63;color:white'
        this.buttonColor4 = ''
      }else if (selected.target.innerText == 'FAQ') {
        this.currentComponent = 'MemberBoardsFAQ'
        this.buttonColor1 = ''
        this.buttonColor2 = ''
        this.buttonColor3 = ''
        this.buttonColor4 = 'background-color:#E91E63;color:white'
      }

      console.log(this.currentComponent)
    },
  }
}
</script>

<style lang="css">
</style>
