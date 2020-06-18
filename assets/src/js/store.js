import Vue from 'vue'
import axios from 'axios'
import Vuex from 'vuex'
import router from './router'


Vue.use(Vuex)

export default new Vuex.Store({

	state: {
		isLogged: localStorage.getItem('token'),
		currentUser: {},
		role: 'null',
		Tutor: [],
	LevelTestError: {},
	RegularClassError: {},


},

	getters: {
		getCurrentUser: state => {

				return state.currentUser
		},

		getUserPosition: state => {

			return state.currentUser.position
		},

		getTutor: state => {
			return state.Tutor
		},

		userStatus: state => {
			return state.isLogged
		},

		userRole: state => {
			return state.role
		},

		getLeveltestError: state => {

			return state.LevelTestError
		},

		getRegularclassError: state => {

			return state.RegularClassError
		}




	},

	actions: {
		signIn(context, data) {

			console.log(data, 'data')

			const {token, user} = data


			if (token) {

				const ph_teachers = ['team_leader', 'assistant_team_leader', 'assistant_head_tutor', 'head_tutor', 'training_officer', 'operations manager', 'marketing_manager', 'tutor']
				const tl = ['team_leader', 'assistant_team_leader']
				const admin = ['team_leader', 'assistant_team_leader', 'assistant_head_tutor', 'head_tutor', 'training_officer', 'operations manager', 'kr_manager', 'marketing_manager']
				const ph_admin = ['team_leader', 'assistant_team_leader', 'assistant_head_tutor', 'head_tutor', 'training_officer', 'operations manager', 'marketing_manager']
				const kr_admin = ['kr_manager']
				const student = ['student']

				context.commit('logged')


				this.state.currentUser = user


				localStorage.setItem('token', token)



					if(student.includes(user.position.toLowerCase())){

						router.push('/StudentDashboard')
					}

					if(ph_teachers.includes(user.position.toLowerCase())){

						router.push('/tutor_page')
					}

					if(kr_admin.includes(user.position.toLowerCase())){

							router.push('/MemberBoards')
					}




			}



		},

		checkAuth(context, data){

			if(localStorage.getItem('token')) {

				axios.get('Role/getRole').then( res => {



					if(res.data){
						const user  = res.data
						context.commit('setAuth', user)
						return user
					}
				})
			}
		},




		setTutor(context, data) {
			console.log(data.Tutor, 'Tutor')
			context.commit('setTutor', data.Tutor)
			router.push('/MemberAddTutor2')
		},

		addTutor(context, data) {


			const form = new FormData()


			form.append('mega_name', data.Tutor.mega_name)
			form.append('position', data.Tutor.position)
			form.append('first_name', data.Tutor.first_name)
			form.append('last_name', data.Tutor.last_name)
			form.append('sex', data.Tutor.sex)
			form.append('date_of_birth', data.Tutor.date_of_birth)
			form.append('address', data.Tutor.address)
			form.append('major', data.Tutor.major)
			form.append('school', data.Tutor.school),
			form.append('workexp', data.Tutor.workexp)
			form.append('introduction', data.Tutor.introduction)
			form.append('specialty', data.Tutor.specialty)
			form.append('email', data.Tutor.email)
			form.append('mobile_number', data.Tutor.mobile_number)
			form.append('id', data.Tutor2.id)
			form.append('pw', data.Tutor2.pw)
			form.append('confirm_password',data.Tutor2.confirm_password)
			form.append('academies', data.Tutor2.academies)
			form.append('affiliation', data.Tutor2.affiliation)
			form.append('am', data.Tutor2.am)
			form.append('class_type', data.Tutor2.class_type)
			form.append('end_am', data.Tutor2.end_am)
			form.append('end_pm', data.Tutor2.end_pm)
			form.append('language', data.Tutor2.language)
			form.append('pm', data.Tutor2.pm)
			form.append('start_am', data.Tutor2.start_am)
			form.append('start_pm', data.Tutor2.start_pm)
			form.append('starting_date', data.Tutor2.starting_date)
			form.append('workplace', data.Tutor2.workplace)
			form.append('country', data.Tutor2.country)
			form.append('team', data.Tutor2.team)
			form.append('files', data.Tutor.files)
			console.log(data.Tutor, 'adsada')

			axios.post('Tutor/addTutor', form).then(res => {
				console.log(res, 'res')

				if(res.data.error === false || res.status === 200){

					location.reload()
				}

			}).catch(err => {
				console.log(err)
			})



		},

		updateTutor(context, data) {


			const form = new FormData()

			form.append('idx', data.Tutor.idx)
			form.append('mega_name', data.Tutor.mega_name)
			form.append('position', data.Tutor.position)
			form.append('first_name', data.Tutor.first_name)
			form.append('last_name', data.Tutor.last_name)
			form.append('sex', data.Tutor.sex)
			form.append('date_of_birth', data.Tutor.date_of_birth)
			form.append('address', data.Tutor.address)
			form.append('major', data.Tutor.major)
			form.append('school', data.Tutor.school),
			form.append('workexp', data.Tutor.workexp)
			form.append('introduction', data.Tutor.introduction)
			form.append('specialty', data.Tutor.specialty)
			form.append('email', data.Tutor.email)
			form.append('mobile_number', data.Tutor.mobile_number)
			form.append('files', data.Tutor.files)
			form.append('recording_path', data.Tutor.recording_path)
			console.log(data.Tutor.files, 'adsada')

			axios.post('Tutor/updateTutor', form).then(res => {
				console.log(res.data)
				if(res.data){

location.reload()
				}

			}).catch(err => {
				console.log(err)
			})



		},





		setManager(context,data) {

			const form = new FormData()


			form.append('mega_name', data.Tutor.mega_name)
			form.append('position', data.Tutor.position)
			form.append('first_name', data.Tutor.first_name)
			form.append('last_name', data.Tutor.last_name)
			form.append('sex', data.Tutor.sex)
			form.append('date_of_birth', data.Tutor.date_of_birth)
			form.append('address', data.Tutor.address)
			form.append('major', data.Tutor.major)
			form.append('school', data.Tutor.school),
			form.append('workexp', data.Tutor.workexp)
			form.append('introduction', data.Tutor.introduction)
			form.append('specialty', data.Tutor.specialty)
			form.append('email', data.Tutor.email)
			form.append('mobile_number', data.Tutor.mobile_number)
			form.append('id', data.Tutor.id)
			form.append('pw', data.Tutor.pw)
			form.append('confirm_password',data.Tutor.confirm_password)
			form.append('team', data.Tutor.team)
			form.append('start_am', data.Tutor.start_am)
			form.append('end_pm', data.Tutor.end_pm)

			axios.post('Tutor/addManager', form).then(res => {
				console.log(res.data, 'res')

				location.reload()
			}).catch(err => {
				console.log(err)
			})



		},

		addLevelTest(context, data) {
			console.log(data)
			const form = new FormData()

			if (data.Member.name) {
				form.append('name', data.Member.name)
			}

			if (data.Member.kr_name) {
				form.append('kr_name', data.Member.kr_name)
			}

			if (data.Member.phone_number) {
				form.append('phone_number', data.Member.phone_number)
			}
			if (data.Member.academy) {
				form.append('academy', data.Member.academy)

			}
			if (data.Member.class_type) {
				form.append('class_type', data.Member.class_type)
			}

			if (data.Member.date) {
				form.append('date', data.Member.date)
			}
			if (data.Member.hour) {
				form.append('hour', data.Member.hour)
			}

			if (data.Member.minute) {
				form.append('minute', data.Member.minute)
			}

			if (data.Member.selectedTutor) {
				form.append('selectedTutor', data.Member.selectedTutor)
			}
			if (data.Member.duration) {
				form.append('duration', data.Member.duration)
			}

			if (data.Member.class_start) {

				form.append('class_start', data.Member.class_start)
			}

			if (data.Member.class_end) {

				form.append('class_end', data.Member.class_end)
			}

			if (data.Member.applicable_days) {

				form.append('applicable_days', data.Member.applicable_days)
			}

			if (data.Member.skypeId) {

				form.append('skypeId', data.Member.skypeId)
			}


			axios.post('Leveltest/addLevelTest', form).then(res => {



				var test =  res.data.substring(1);



				console.log(test, 'test')

				var parseData = JSON.parse(test)


				console.log(parseData.msg, 'msg')

				console.log(parseData.error, 'err')

if(parseData.error){


	context.commit('leveltestError', parseData.msg)

	console.log('parse')
}
else{


	this.state.LevelTestError = {}
}







			}).catch(err => {

				console.log(err, 'err')
			})
		},


		addRegularClass(context, data) {

			console.log(data, 'datainfo')
			const form = new FormData()
			form.append('id', data.Member.id ? data.Member.id : '')
			form.append('pw', data.Member.pw ? data.Member.pw : '')
			form.append('name', data.Member.name ? data.Member.name : '')
			form.append('kr_name', data.Member.kr_name ? data.Member.kr_name : '')
			form.append('academy', data.Member.academy ? data.Member.academy : '')
			form.append('level', data.Member.level ? data.Member.level : '')
			form.append('class_type', data.Member.class_type ? data.Member.class_type : '')
			form.append('date', data.Member.date ? data.Member.date : '')
			form.append('applicable_days', data.Member.applicable_days ? data.Member.applicable_days : '')
			form.append('hour', data.Member.hour ?  data.Member.hour : '')
			form.append('minute', data.Member.minute ? data.Member.minute : '')
			form.append('duration', data.Member.duration ?  data.Member.duration : '')
			form.append('period', data.Member.period ? data.Member.period : '')
			form.append('days', data.Member.days ? data.Member.days : '')
			form.append('selectedTutor', data.Member.selectedTutor ? data.Member.selectedTutor : '')
			form.append('class_start', data.Member.class_start ? data.Member.class_start : '')
			form.append('class_end', data.Member.class_end ? data.Member.class_end : '')
			form.append('price', data.Member.price ? data.Member.price  : '')
			form.append('curriculum', data.Member.curriculum ? data.Member.curriculum : '')
			form.append('bookMaterial', data.Member.bookMaterial ?  data.Member.bookMaterial : '')
			form.append('phone_number', data.Member.phone_number ?  data.Member.phone_number : '')
			form.append('email', data.Member.email?  data.Member.email : '')
			form.append('level', data.Member.level ?  data.Member.level: '')
			form.append('preference_number', data.Member.preference_number ?  data.Member.preference_number: '')
			form.append('skypeId', data.Member.skypeId ?  data.Member.skypeId : '')







			axios.post('Regularclass/addRegularClass', form).then(res => {


				var test =  res.data.substring(1);

console.log(test, 'test')

	if(!test){

			this.state.RegularClassError = {}
	}
				var parseData = JSON.parse(test)




if(parseData.error){


	context.commit('regularclassError', parseData.msg)


}

else{


	this.state.RegularClassError = {}
}


			}).catch(err => {

				console.log(err)
			})

		}





	},

	mutations: {

		logged(state, data) {
			state.isLogged = true
		},

		setAuth(state, data) {

			state.currentUser = data

			Vue.prototype.$position = data

			console.log(data, 'datatata')
		},

		setTutor(state, data) {
			state.Tutor = data
			console.log(state.Tutor, 'state')

		},

		leveltestError(state, data){


			console.log(data, 'data')
			state.LevelTestError = data

			console.log(state.LevelTestError, 'ddate')
		},

		regularclassError(state, data){


			console.log(data, 'data')
			state.RegularClassError = data

			console.log(state.RegularClassError, 'ddate')
		}

	}
})
