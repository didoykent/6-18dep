import Vue from 'vue'
import Vuex from 'vuex'
import VueRouter from 'vue-router'


import axios from 'axios'
import store from './store'
Vue.use(VueRouter)



let role = ''
























const tlAuth =

 (to, from, next) => {
   if(localStorage.getItem('token')) {

     axios.get('Role/getRole').then( res => {


       console.log(res.data, 'data')
       if(res.data){
         const user  = res.data
         role = user.position.toLowerCase()

         console.log(role, 'role')
         if(tl.includes(role)){


           next()

         }

         else{

           next('/login')
         }
       }
     }).catch(err => {

       console.log(err)
     })
   }
    }



const ph_teachers_auth =   (to, from, next) => {
  if(localStorage.getItem('token')) {

    axios.get('Role/getRole').then( res => {


      console.log(res.data, 'data')
      if(res.data){
        const user  = res.data
        role = user.position.toLowerCase()

        console.log(role, 'role')
        if(ph_teachers.includes(role)){


          next()

        }

        else{

          next('/login')
        }
      }
    }).catch(err => {

      console.log(err)
    })
  }
    }

const adminAuth =   (to, from, next) => {
  if(localStorage.getItem('token')) {

    axios.get('Role/getRole').then( res => {


      console.log(res.data, 'data')
      if(res.data){
        const user  = res.data
        role = user.position.toLowerCase()

        console.log(role, 'role')
        if(admin.includes(role)){


          next()

        }

        else{

          next('/login')
        }
      }
    }).catch(err => {

      console.log(err)
    })
  }
    }



const ph_adminAuth =

(to, from, next) => {
  if(localStorage.getItem('token')) {

    axios.get('Role/getRole').then( res => {


      console.log(res.data, 'data')
      if(res.data){
        const user  = res.data
        role = user.position.toLowerCase()

        console.log(role, 'role')
        if(ph_admin.includes(role)){



          next()

        }

        else{

          next('/login')
        }
      }
    }).catch(err => {

      console.log(err)
    })
  }
  }



const kr_admin_auth =



  (to, from, next) => {

    if(localStorage.getItem('token')) {

      axios.get('Role/getRole').then( res => {


        console.log(res.data, 'data')
        if(res.data){
          const user  = res.data
          role = user.position.toLowerCase()

          console.log(role, 'role')
          if(kr_admin.includes(role)){


            next()

          }

          else{

            next('/login')
          }
        }
      }).catch(err => {

        console.log(err)
      })
    }



    }



const studentAuth   =   (to, from, next) => {
  if(localStorage.getItem('token')) {

    axios.get('Role/getRole').then( res => {


      console.log(res.data, 'data')
      if(res.data){
        const user  = res.data
        role = user.position.toLowerCase()

        console.log(role, 'role')
        if(student.includes(role)){




            next()




        }

        else{

          next('/login')
        }
      }
    }).catch(err => {

      console.log(err)
    })
  }
    }




const router = new VueRouter({


  routes: [

{path: '/dashboard',  name: 'admin',  component:require('./components/Dashboard.vue').default,  beforeEnter:kr_admin_auth},
{path: '/Member',   name: 'admin', component:require('./components/Member.vue').default,  beforeEnter:kr_admin_auth},
{path: '/MemberTutor',   name: 'admin', component:require('./components/MemberTutor.vue').default,  beforeEnter:kr_admin_auth},
{path: '/MemberTutorUEducation',   name: 'admin', component:require('./components/MemberTutorUEducation.vue').default,   beforeEnter:kr_admin_auth},
{path: '/MemberAddTutor',   name: 'admin', component:require('./components/MemberAddTutor.vue').default,  beforeEnter:kr_admin_auth},
{path: '/MemberAddTutor2',   name: 'admin', component:require('./components/MemberAddTutor2.vue').default,  beforeEnter:kr_admin_auth},
{path: '/MemberAddStudent',  name: 'admin', component:require('./components/MemberAddStudent.vue').default,  beforeEnter:kr_admin_auth},
{path: '/MemberAddStudent2',   name: 'admin', component:require('./components/MemberAddStudent2.vue').default,  beforeEnter:kr_admin_auth},
{path: '/ClassesMyClass',    name: 'admin', component:require('./components/ClassesMyClass.vue').default,  beforeEnter:kr_admin_auth},

{path: '/MemberStudentEvaluation/:classid',  name: 'tutorpage', component:require('./components/MemberStudentEvaluation.vue').default},
{path: '/MemberStudentEvaluation2/:classid',  name: 'tutorpage', component:require('./components/MemberStudentEvaluation2.vue').default},
{path: '/LevelTestStudentEvaluation/:classid',  name: 'tutorpage', component:require('./components/MemberLeveltestEvaluation.vue').default},
{path: '/LevelTestStudentEvaluation2/:classid',  name: 'tutorpage', component:require('./components/MemberLeveltestEvaluation2.vue').default},
{path: '/MemberClass',   name: 'admin', component:require('./components/MemberClass.vue').default, beforeEnter:kr_admin_auth},
{path: '/MemberBoards',   name: 'admin', component:require('./components/MemberBoards.vue').default, beforeEnter:kr_admin_auth},
{path: '/PriceTable', component:require('./components/PriceTable.vue').default, beforeEnter:kr_admin_auth},
{path: '/tutor_page', name: 'tutorpage', component: require('./schedule/TutorPage.vue').default, beforeEnter:ph_teachers_auth},
{path: '/tutor_writing_correction', name: 'tutorpage', component: require('./components/TutorWritingCorrection.vue').default, beforeEnter:ph_teachers_auth},
{path: '/tutor_announcement', name: 'tutorpage', component: require('./components/TutorAnnouncement.vue').default, beforeEnter:ph_teachers_auth},
{path: '/tutor_create_meeting', name: 'tutorpage', component: require('./components/TutorZoomMeeting.vue').default, beforeEnter:ph_teachers_auth},
{path: '/login',  component: require('./authentication/SignIn.vue').default},
{path: '/TeamMember', name: 'team_leader', component:require('./components/TeamMember.vue').default, beforeEnter:tlAuth},
{path: '/MemberViewClasses/:idx', name: 'team_leader', component:require('./components/SelectedMemberClasses.vue').default, beforeEnter:tlAuth},
{path: '/StudentDashboard', name: 'student', component:require('./Student/StudentDashboard.vue').default, beforeEnter:studentAuth},
{path: '/StudentWritingCorrection', name: 'student', component:require('./Student/StudentWritingCorrection').default, beforeEnter:studentAuth},
{path: '/StudentQA', name: 'student', component:require('./Student/StudentQA').default , beforeEnter:studentAuth},
{path: '/StudentFAQ', name: 'student', component:require('./Student/StudentFAQ').default , beforeEnter:studentAuth},
{path: '/StudentZoom/:tutor_data/:class_data', name: '', component:require('./Student/StudentZoom').default},


  { path: '*', redirect: '/login' }


  ]
})




const ph_teachers = ['team_leader', 'assistant_team_leader', 'assistant_head_tutor', 'head_tutor', 'training_officer', 'operations manager', 'marketing_manager', 'tutor']
const tl = ['team_leader', 'assistant_team_leader']
const admin = ['team_leader', 'assistant_team_leader', 'assistant_head_tutor', 'head_tutor', 'training_officer', 'operations manager', 'kr_manager', 'marketing_manager']
const ph_admin = ['team_leader', 'assistant_team_leader', 'assistant_head_tutor', 'head_tutor', 'training_officer', 'operations manager', 'marketing_manager']
const kr_admin = ['kr_manager']
const student = ['student']

export default router
